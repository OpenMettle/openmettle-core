# 0044 — OpenMettle's own inference proxy and binding-free dispatch

Accepted with its implementation, 23 November 2026 (V1-06 proxy increments 2a and 2b). Refs #7.
Supersedes [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) in part: see
[What ADR 0037 still decides](#what-adr-0037-still-decides) and [Superseded](#superseded).
Builds on [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md) (leases),
[ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md) (the admission
snapshot), [ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md) (holds and
lock order) and [ADR 0043](0043-packaged-worker-inference-configuration.md) (the packaged
worker, which announced this decision).

## Problem

ADR 0037 put a third-party gateway between OpenMettle and the model server. OpenMettle was to
provision one virtual key per user on that gateway through its admin API, seal the key into
PostgreSQL, hand it to the caller at dispatch and reconcile the gateway's usage records.

Three findings ended that design:

- **The candidates were rejected.** The third-party gateways that were tested for this role
  were rejected, and on 23 November 2026 the owner decided that no deployment will contain
  one.
- **Provisioning was never wired.** The reconciler, the admin client and the publication of a
  key generation are library code that only tests call. No binary runs them, and the remote
  admin API they need will never exist.
- **Handoff was therefore unreachable.** `openmettle.gateway_handoff` returns no row without a
  `ready` gateway binding, an active key generation and a matching policy row. Nothing can
  create those rows in a real deployment, so no request could ever be dispatched.

Increment 1 delivered `openmettle-gateway`, a forwarding and metering proxy. It had no caller
authentication, forwarded the same request any number of times and did not check the model.

## Decision

OpenMettle runs its own proxy. The proxy shares the application's PostgreSQL database under the
existing `openmettle_gateway` role and holds no per-user state of its own.

Increments 2a and 2b deliver this decision: 2a the database and library half (the handoff, the
worker's credential and the dispatch function), 2b the proxy half.

### Authorization without a binding

A run round is handed off by `openmettle.gateway_handoff_round(request, dispatch secret, lease)`,
callable by `openmettle_worker` only. It is `gateway_handoff` for a run-owned request, with the
approval as the root of the check where a key generation and its policy row were. It keeps
every check of that function that does not concern a binding, generation, policy or session:
the live lease, cancellation, the execution deadline, the round limit, the enabled user, the
active and unexpired approval, the provider's current revision, platform and user capability
denies, opt-in capability grants, the project's archived and deleted marks and write access to
the conversation.

What the policy row supplied now comes from sources that are already authoritative:

| Policy row field | Replacement |
| --- | --- |
| `model` | The request's model must equal `effective.model` of the run's admission snapshot. |
| `capabilities` | `required_capabilities` of the same snapshot (`on_by_default` or `opt_in`). |
| `revision` and the provider, approval and user generations | None. They fenced a stored policy against the live rows; the function reads the live rows. |
| `grant_cycle` | A live editor or owner project role, read at handoff. |
| `report_source` | The request's installation. |

The snapshot must be an `openmettle.conversation` version 1 document with a string model and an
object of known capability gates under valid capability names, and no key may repeat at any
depth: `jsonb` would silently keep the last one. Anything else refuses the round: there is no
fallback to an unchecked model or to no required capability. A new snapshot format or version
therefore requires a new version of this function before its runs can be dispatched.

The function requires `READ COMMITTED` and reads the authority after its last lock. Its lock
order is `gateway_handoff`'s order without the session and binding locks: account
administration, project, provider and approval, user, run, reservation, request. Removing locks
from an established order cannot create an inversion.

**The last time check precedes nothing that can wait.** After the handoff the worker's
transaction still commits the quota holds, and the deferred handoff check runs at commit. Both
can wait on quota locks, and an approval, a lease or a membership observation can lapse during
that wait. The transaction therefore ends with
`openmettle.gateway_handoff_round_confirm(request, dispatch secret, lease)`: it runs every
deferred check at once, then reads the same authority again on a new clock reading, and aborts
the transaction if it is gone. That read takes no lock, and the commit that follows has no
deferred work left, so no lock wait can follow the last time check. The time a commit spends
on durability is not covered. The worker's order is: the ADR 0040 prefix lock, the handoff, the
outbound-header validation, the quota commit, the confirm step, commit.

A handed-off request without a binding keeps `binding_id`, `generation` and `policy_revision`
null, belongs to a run and reports under its installation. A named CHECK replaces migration
23's unnamed one and allows exactly those two shapes of a handed-off request.

### The dispatch secret is the caller credential

Reservation already creates a 32-byte random dispatch secret, stores only its SHA-256 and keeps
the secret in a handle that cannot be cloned or serialized. That secret is now the caller's
credential. The worker sends it as `Authorization: Bearer`, in unpadded base64url, on the
request the handoff committed, with the request ID in `x-request-id`. Only the worker that
reserved the round holds it, and it is useless for any other request.

### One dispatch per request

`openmettle.gateway_dispatch(request, SHA-256 of the dispatch secret)`, callable by
`openmettle_gateway` only, sets `gateway_requests.dispatched_at` once and returns the stored
routing fields: installation, scope, report source, principal and model. A later call with the
same hash reports a replay. Every other call returns no row. The caller cannot tell the reasons
apart.

The proxy hashes the secret its caller presented and sends only the hash. The secret itself
never crosses a database connection, so a server that logs statement parameters records
nothing a caller could present to the proxy. The hash is what the request row already stores.

A first dispatch is granted only to a request that was handed off without a binding, has no
settlement, and whose run is running, not cancelled and inside its lease and its execution
deadline on a clock reading taken after the row lock. A request handed off under ADR 0037 is
never dispatched here: its transport may already have sent it. It remains eligible for
settlement only.

`dispatched_at` is a column, not a state: settlement and the quota functions test
`state = 'handed_off'`. The function locks only the request row, which is also settlement's
first lock, waits for it before deciding, and never writes `state`, so the deferred handoff
trigger does not fire.

The principal of a dispatched request is the actor's user ID. Settlement accepts the binding's
principal where a binding exists and the actor otherwise, so rows handed off under ADR 0037
still settle. Settlement refuses a report for a request without a binding that was never
dispatched: the proxy is the only reporter, and it reports after it spent the dispatch.

### The proxy is the only usage witness and the only model check

The proxy requires exactly one end-to-end `Authorization: Bearer` header holding 32 bytes. It
spends the dispatch before it reads the body, so an unauthenticated caller never has a body
buffered. No row answers `401`, a replay `409`, and nothing is sent upstream in either case.

The recorded SGLang server answers any model name from its loaded model. The proxy therefore
has one required setting, `OPENMETTLE_GATEWAY_MODEL`, naming the catalog model its upstream
serves. It refuses a request reserved for another model, and a body whose top-level `model` is
not that model exactly once. The body is still forwarded byte for byte.

A refusal after the dispatch was spent, and a dispatch whose database exchange did not answer,
leave the hold in place and one `gateway.usage.unrecorded` event with a fixed reason.

No other component observes usage. The proxy writes the one final report of a request from the
upstream's own usage object, as in increment 1.

## What ADR 0037 still decides

- Reservation: the run-level admission hold, the per-round request, its dispatch secret and
  release.
- The handed-off state, and that a handoff commits with its quota holds or not at all.
- The settlement ledger: usage reports, settlements, revisions, finality and the quota fold.
- The caller-facing error contract.

## Superseded

Per-user virtual keys and their generations; sealing and the key ring; remote reconciliation,
intents and their audit trail; the admin profile and its client.

### Left in place, unused, until increment 6

Removing this code is a separate increment so that this one stays reviewable. Until then the
following exists and nothing in a deployment reaches it:

- Tables `gateway_bindings`, `gateway_generations`, `gateway_nonces`, `gateway_policy`,
  `gateway_intents` and `gateway_audit`, with their grants.
- The columns `binding_id`, `generation` and `policy_revision` of `gateway_requests` and their
  three foreign keys.
- SQL function `openmettle.gateway_handoff`.
- `src/authz/gateway/reconcile.rs`.
- `Pending::handoff`, `handoff_in`, `intent` and `publish_generation` in `src/authz/gateway.rs`.
- The usage backfill (`settlement::Backfill`) and its `backfill.sql` and `legacy_backfill.sql`.
- The admin client (`src/provider_http/gateway.rs`) and `gateway/profile.rs`, except
  `UsageReport`, which settlement uses.
- The gateway key ring and sealer (`src/provider_keys/gateway.rs`), and the worker document's
  `gateway_keys` member, which the worker still loads and no longer uses.
- The family-policy client flag.

### Session callers

`gateway::reserve` with a session and `Pending::handoff` have no caller outside tests: no API
route performs a caller-owned completion. That path stays on the unreachable
`gateway_handoff`. It is deleted with the code above or rebuilt on this design when a caller
exists.

## Alternatives

- **Keep per-user keys and have the proxy verify them.** Rejected: it keeps sealing, rotation
  and a key ring to protect a credential that the dispatch secret already is.
- **A shared static credential between worker and proxy.** Rejected: it authenticates the
  worker, not the request, and would not make a dispatch single-use.
- **A new request state for dispatched.** Rejected: settlement and every quota function test
  `handed_off`; a column changes none of them.
- **Keep policy rows, written by the API at admission.** Rejected: they would duplicate the
  admission snapshot and need the fences this decision removes.
- **Let the model server check the model.** Not available: the recorded server does not.

## Consequences

- A deployment needs no gateway provisioning. A round is authorized against live rows at
  handoff, so a role granted again after it was removed authorizes again; ADR 0037's pinned
  grant cycle did not.
- A dispatch that is spent and then fails before the upstream answers cannot be retried under
  the same request.
- Migration 29 adds one column and four functions and replaces one CHECK. It needs no
  activation step and no backfill, and it must be applied before workers of this release run.
- ADR 0043 said the replacement would change `installation`, `gateway_keys` and one method of
  the worker and nothing else. `installation` stays and is now also the report source, and the
  turn executor's handoff call lost its key ring argument. Increment 2c updates that record.

## Delivery

| Increment | Content |
| --- | --- |
| 1 | Forward one request and record its usage (merged). |
| 2a | Migration 29: binding-free run-round handoff and the dispatch function; the dispatch secret as the worker's bearer. |
| 2b | Proxy authentication, single dispatch and model check. |
| 2c | Worker document cleanup; packaged worker to TLS terminator to proxy end-to-end test; update ADR 0043 and the worker page. |
| 3 | Explicit reports for incomplete responses. |
| 4 | Family policy tables. |
| 5 | Cache separation. |
| 6 | Removal of the superseded code and tables. |
| 7 | Deployment, TLS and network policy. |

## Open points

- **Cleartext secret.** The worker's transport requires `https://` and the proxy listens on
  plain HTTP, so the two cannot be connected yet. Connected without TLS, the dispatch secret
  would cross the network in cleartext. The proxy stays undeployable until increment 7.
- **Holds without a final report.** A handed-off request keeps its hold until a final report
  arrives. A round that is never dispatched, is refused after its dispatch was spent, or whose
  response carries no usage keeps that hold indefinitely until increment 3.
- **Broad database role.** `openmettle_gateway` still has the grants the reconciler needed. A
  network-facing process needs only the dispatch and settlement functions. Increment 6
  narrows the role.
- **Family policy** is enforced nowhere until increment 4.

## Evidence

- `tests/schema/gateway_rounds.rs`: both functions under the provisioned role logins, with no
  binding, generation or policy row: each withdrawn authority, snapshot shapes, role and
  isolation restrictions, concurrent dispatch, the CHECK and settlement.
- `tests/schema/gateway_proxy.rs`: the binary against the recorded SGLang stand-in, with rounds
  reserved and handed off through the library and their quota holds.
- `tests/schema/gateway.rs`: a bound request handed off at version 23 passes migration 29 and
  settles under its binding's principal, and is never given a dispatch.
- `tests/schema/worker_leases.rs` and `tests/schema/quotas.rs`: the worker and the library hand
  rounds off with their quota holds, and the worker sends the round's dispatch secret as its
  bearer.
- `src/gateway_proxy.rs` and `tests/runtime.rs`: credential and model parsing, the model
  setting, and refusals through the binary without a database.
