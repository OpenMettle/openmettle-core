# 0044 — OpenMettle's own inference proxy and binding-free dispatch

Accepted with its implementation, 23 November 2026 (V1-06 proxy increments 2a and 2b); increment
2c delivered 24 November 2026. Amended 24 November 2026 with increment 3a: see
[requests that end without usage](#amendment-24-november-2026-requests-that-end-without-usage).
Refs #7.
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

A run round is handed off by
`openmettle.gateway_handoff_round(request, dispatch secret, lease, SHA-256 of the bearer)`,
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

That last check is a guarantee of the library's transaction, not of the database. A direct SQL
caller with the worker role could call the handoff and commit without the confirm step. That
is within ADR 0033's worker trust model, which excludes arbitrary SQL under the worker's
credentials: that role can already forge any run transition.

A handed-off request without a binding keeps `binding_id`, `generation` and `policy_revision`
null, belongs to a run, reports under its installation and carries the two digests described
next. A named CHECK replaces migration 23's unnamed one and allows exactly those two shapes of
a handed-off request.

### A bearer of its own is the caller credential

Reservation creates a 32-byte random dispatch secret and stores only its SHA-256. That secret
stays what it was: the reserving caller's proof to the database for release, the quota commit
and the handoff. The worker sends it to PostgreSQL as a statement parameter, so it must not
also be what the proxy accepts.

For each handoff the worker therefore makes a second, independent 32-byte random value, the
bearer. It passes only the bearer's SHA-256 to the handoff, which stores it in
`gateway_requests.bearer_hash`. The column is written by the handoff alone, together with the
handed-off state, and only for a request without a binding. The worker keeps the bearer in
the single-use dispatch handle, which cannot be cloned, printed or serialized, and no database
function returns it.

- The worker generates the bearer and sends it to the proxy over HTTP, as
  `Authorization: Bearer` in unpadded base64url, on the request the handoff committed, with
  the request ID in `x-request-id`. The proxy receives and decodes it.
- Both components send only its SHA-256 to PostgreSQL.
- The dispatch secret crosses only the worker's database connection. It is never sent over
  HTTP and the proxy does not accept it: the dispatch compares `bearer_hash` only, and the
  CHECK keeps that hash different from the dispatch secret's.
- No zeroization guarantee is made for either value in either process.

The handoff also stores `claim_hash`, the SHA-256 of the run claim that authorized it. The claim
token itself is not stored there, because the gateway role can read the table.

### One dispatch per request

`openmettle.gateway_dispatch(request, SHA-256 of the bearer)`, callable by `openmettle_gateway`
only, sets `gateway_requests.dispatched_at` once and returns the stored routing fields:
installation, scope, report source, principal and model. A later call with the same hash
reports a replay. Every other call returns no row. The caller cannot tell the reasons apart.

The proxy hashes the bearer its caller presented and sends only the hash, so a server that
logs statement parameters records nothing a caller could present to the proxy.

A first dispatch is granted only to a request that was handed off without a binding, has no
settlement, and whose run is running, not cancelled, still held under the claim that
authorized the handoff, and inside its lease and its execution deadline. A run that another
holder reclaimed does not make the previous holder's unspent round dispatchable again; a
holder that renews its lease keeps its claim.

The dispatch locks the run row for share, then the request row, and decides after both. It
waits for a release, reclaim, renewal or cancellation in flight, and none can commit between
its decision and its own commit. Run before request is the order of the handoff, the release
and the recovery functions; settlement locks the request and never a run. A caller that does
not prove the bearer locks nothing. The clock is read once, inside the statement that records
the dispatch, after both row locks and that statement's relation locks: that one reading is
compared with the deadlines and stored. A request handed off under ADR 0037 has no bearer
hash and is never dispatched here: its transport may already have sent it. It remains
eligible for settlement only.

`dispatched_at` is a column, not a state: settlement and the quota functions test
`state = 'handed_off'`. The function never writes `state`, so the deferred handoff trigger
does not fire.

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
leave one `gateway.usage.unrecorded` event with a fixed reason. Since increment 3a the refusal
also closes the hold (see the amendment); the unanswered dispatch still leaves it in place.

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
- The gateway key ring and sealer (`src/provider_keys/gateway.rs`) and the API document's
  `gateway_keys` member. The worker no longer has either (increment 2c).
- The family-policy client flag.

### Session callers

`gateway::reserve` with a session and `Pending::handoff` have no caller outside tests: no API
route performs a caller-owned completion. That path stays on the unreachable
`gateway_handoff`. It is deleted with the code above or rebuilt on this design when a caller
exists.

## Alternatives

- **Keep per-user keys and have the proxy verify them.** Rejected: it keeps sealing, rotation
  and a key ring to protect a credential that a per-round bearer replaces.
- **The dispatch secret as the bearer.** Rejected in review: the worker sends that secret to
  PostgreSQL as a statement parameter, so a server that logs parameters would record a
  credential the proxy accepts.
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
  the same request. Neither can a round whose run was reclaimed before the dispatch: the new
  holder reserves a round of its own.
- A dispatch in flight holds its run: a release, renewal or cancellation waits for it to
  commit, and a reclaim skips the run meanwhile.
- Migration 29 adds three columns and four functions and replaces one CHECK. It needs no
  activation step and no backfill, and it must be applied before workers of this release run.
- ADR 0043 said the replacement would change `installation`, `gateway_keys` and one method of
  the worker and nothing else. `installation` stays and is now also the report source, the
  turn executor's handoff call lost its key ring argument, and increment 2c removed
  `gateway_keys` from the worker document and its routes. ADR 0043 carries a dated note.

## Delivery

| Increment | Content |
| --- | --- |
| 1 | Forward one request and record its usage (merged). |
| 2a | Migration 29: binding-free run-round handoff and the dispatch function; a per-round bearer for the worker. |
| 2b | Proxy authentication, single dispatch and model check. |
| 2c | The worker reaches the proxy over `http://` inside the cluster or `https://` through a TLS terminator; `gateway_keys` removed from the worker document; packaged worker to proxy end-to-end tests; ADR 0043 note and the worker page (delivered 24 November 2026). |
| 3a | A dispatched request that ends without usage is closed by a final report with its reason; migration 31 (delivered 24 November 2026, see the amendment). |
| 3b | A sweep closes the requests the proxy cannot: never dispatched, or never reported. |
| 3c | A response stopped at its token limit ends the turn with its partial output and a marker. |
| 3d | Running usage for cut streams. |
| 4 | Family policy tables. |
| 5 | Cache separation. |
| 6 | Removal of the superseded code and tables. |
| 7 | Deployment, TLS and network policy. |

## Open points

- **Plain HTTP in the cluster.** On 24 November 2026 the owner decided that HTTPS need not be
  enforced inside the cluster and stays an option. The worker's route to the proxy may
  therefore be `http://`, and only that route of the shared provider transport: every other
  client built on it keeps `https://`. The proxy's own client for its SGLang upstream is plain
  HTTP by design (increment 1). A plain route reaches only addresses inside its configured
  ranges, never a public one, and sends only a round that was handed off. The round's bearer
  and the prompt and response bodies then cross the cluster network unencrypted, and an
  interceptor could alter the answer and token counts the worker stores; the proxy settles
  the upstream's own usage. The bearer authorizes one dispatch of one request; a NetworkPolicy admitting
  only workers to the proxy is the mitigation, and TLS terminated in front of the proxy is
  the stricter option. The proxy has no TLS listener of its own, and mutual TLS is a possible
  later option. The proxy stays undeployable until increments 3 and 7.
- **Holds without a final report.** Increment 3a closes a dispatched request that ends without
  usage. A round that is never dispatched, and one the proxy could not report, keep their hold
  until increment 3b; the amendment lists the cases.
- **Cost holds.** A cost hold never settles on a report with usage, because the proxy reports
  no cost ([issue 166](https://github.com/OpenMettle/openmettle-core/issues/166)).
- **Broad database role.** `openmettle_gateway` still has the grants the reconciler needed. A
  network-facing process needs only the dispatch and settlement functions. Increment 6
  narrows the role.
- **Family policy** is enforced nowhere until increment 4.

## Amendment, 24 November 2026: requests that end without usage

Increment 3a, with migration 31. Refs #7.

### Problem

A handed-off request kept its hold until a final report with both token counts arrived, and
the proxy wrote one only for a completed 200 that carried usage. Every other end of a
dispatched request (a refusal after the dispatch was spent, an upstream error, a cut stream, a
caller that left, an answer without usage) left one log line and the hold, for good: the
remote reconciliation that was to close such requests under ADR 0037 will never exist.

A final report without counts was no way out. Settlement accepted it, marked the request
settled, removed it from the scan of outstanding requests and refused its dispatch, while the
quota fold skipped it and kept the hold.

### Decision

**One record.** A request that ends without usage is closed by a final usage report that
carries the reason in `gateway_usage_reports.incomplete` and no usage, cost or unit fields
of its own. The request stays `handed_off`: releasing it would contradict the handoff CHECK
and the handoff receipt the drift verifier checks. The column is the only place the reason is
stored; a report that carries it must be final and leave all six usage, cost and unit columns
null.

**A closed vocabulary in two groups**, so that the database can tell by value whether the
model server may have worked for the request:

| Group | Reasons |
| --- | --- |
| Nothing was sent upstream | `model_not_served`, `model_mismatch`, `request_body`, `upstream_connect` |
| The request was or may have been sent, and its usage is unknown | `upstream_transport`, `upstream_timeout`, `upstream_status`, `upstream_encoding`, `incomplete`, `caller_disconnected`, `no_usage`, `unparsable` |

**The fold closes the hold.** `quota_gateway_fold` gains one rule: a report that carries a
reason adds no measurement of its own—it carries no usage, cost or unit fields—and settles
the hold at what earlier accepted non-final reports measured (nothing when none carried a
count), releasing the rest. The rule applies to token and cost holds alike. A later final
report with counts still corrects the charge, and no later report without counts lowers one.
The fold is the only place that decides the charge.

**Charging rule: nothing is charged for a request without usage, in either group.** The owner
decided this on 24 November 2026 for now, to be revisited. For the second group the
alternatives are:

- *The last running usage.* The recorded server accepts `continuous_usage_stats` (observed
  24 November 2026): every content chunk then carries a running usage object. It is a lower
  bound: for a client that left after 1.5 s it showed 127 completion tokens where the server's
  own counters showed 208. It needs the worker to ask for it and to accept changing counts,
  and it gives nothing for a non-streamed answer or before the first chunk. Because the fold
  preserves measurements from earlier accepted non-final reports, adopting it needs no schema
  change: a non-final report carries the running counts, followed by the final report carrying
  the reason (increment 3d).
- *The reserved amount.* Nobody gains from leaving early, but a cancelled run, an upstream
  error or a proxy fault costs the user the round's full cap.
- *An estimate* from the bytes relayed. Rejected: it would record numbers nobody measured.

With nothing charged, a user who cancels a run gets the model server's work on it for free.
No partial output reaches a user today, so the gain is unbilled load, bounded by the
concurrency limits. Changing the rule for the second group is a change to the fold's
`incomplete` branch alone.

**Revisions.** The proxy writes its one report of a request, with usage or without, at
revision 1 under the request's own ID. Revision 0 is left to the sweep of increment 3b.
Settlement lets a higher final revision correct a lower one, so a report of the proxy that
arrives after the sweep closed the request replaces the sweep's record, and the sweep can
never replace the proxy's.

**No bare final report.** Settlement and a deferred database trigger refuse a final report
that would leave a request without a binding open: one without both counts and without a
reason, or one whose quota fold was not run. The proxy builds a report without counts only
together with its reason.

### Who closes what

| End of the request | After increment 3a |
| --- | --- |
| Completed 200 with usage | The proxy reports the usage, as before. This includes a response stopped at its token limit: the recorded server stops at exactly the requested `max_completion_tokens` and still reports usage (observed 24 November 2026). |
| Dispatch spent, nothing sent, or sent and no usage (the twelve reasons) | The proxy writes the incomplete report at once, also when its caller has gone. |
| Never dispatched: the worker did not reach the proxy, or the proxy refused the bearer | Nothing. The hold stays until increment 3b. |
| Dispatch recorded but unconfirmed to the proxy (`dispatch_unconfirmed`) | Logged only. The hold stays until increment 3b. |
| The proxy could not write its report, or stopped while relaying | `gateway.usage.failed`, or nothing. The hold stays until increment 3b. |

There is still no local spool: when the database is unavailable the report is lost, the hold
stays, and the failure is logged.

### Evidence

- `tests/schema/gateway_proxy.rs`: every reason through the binary, among them the recorded
  aborted stream and the recorded 500; the hold settled with nothing charged, the request no
  longer outstanding and no accounting drift. Revisions, corrections and the refused bare
  final report through settlement on a metered request.
- `tests/schema/gateway_rounds.rs`: the same for a request without a quota hold, the refusal
  for a request that was never dispatched, and the upgrade from schema 30 with the CHECK.
- `tests/schema/live_turns/worker_gateway.rs`: the packaged worker's round refused by a proxy
  that serves another model is closed with `model_not_served`.

## Evidence

- `tests/schema/gateway_rounds.rs`: both functions under the provisioned role logins, with no
  binding, generation or policy row: each withdrawn authority, snapshot shapes, role and
  isolation restrictions, concurrent dispatch, a reclaimed and a renewed run, a release and
  a reclaim in flight, a lease that runs out during a lock wait, the CHECK and settlement.
- `tests/schema/gateway_proxy.rs`: the binary against the recorded SGLang stand-in, with rounds
  reserved and handed off through the library and their quota holds.
- `tests/schema/live_turns/worker_gateway.rs`: the packaged worker binary claims a queued run
  and dispatches its round to the proxy binary with the bearer it made, over plain HTTP and
  through a TLS terminator; the usage report equals the recorded answer's, the hold settles
  and the answer is published. A proxy serving another model fails the turn and closes the
  hold with `model_not_served`; an unreachable proxy fails the turn and leaves the hold
  until increment 3b.
- `tests/provider_http_support/tests.rs`, `tests/provider_inference/authentication.rs` and
  `tests/provider_gateway.rs`: every other client refuses `http://`, and the gateway route
  pairs its scheme with trust anchors and sends its bearer and request ID without TLS.
- `tests/schema/gateway.rs`: a bound request handed off at version 23 passes migration 29 and
  settles under its binding's principal, and is never given a dispatch.
- `tests/schema/worker_leases.rs` and `tests/schema/quotas.rs`: the worker and the library hand
  rounds off with their quota holds. A recording of every byte one worker process sends to
  PostgreSQL holds the dispatch secret and the bearer's hash, and not the bearer.
- `src/gateway_proxy.rs` and `tests/runtime.rs`: credential and model parsing, the model
  setting, and refusals through the binary without a database.
