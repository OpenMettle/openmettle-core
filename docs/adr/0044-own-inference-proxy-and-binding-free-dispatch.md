# 0044 — OpenMettle's own inference proxy and binding-free dispatch

Accepted with its implementation, 23 November 2026 (V1-06 proxy increments 2a and 2b); increment
2c delivered 24 November 2026. Amended 24 November 2026 with increments 3a (migration 31),
3b (migration 32), 3c (migration 33), proxy cost-hold settlement (migration 34, issue #166) and
increment 4 family policy tables & enforcement (migration 35): see
[requests that end without usage](#amendment-24-november-2026-requests-that-end-without-usage),
[cost-hold settlement from recorded profile pricing](#amendment-24-november-2026-cost-hold-settlement-from-recorded-profile-pricing)
and [family policy tables and enforcement](#amendment-24-november-2026-family-policy-tables-and-enforcement).
Refs #7, #9, #17, #166.
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
also closes the hold (see the amendment); since increment 3b the worker's maintenance sweep
closes an unanswered dispatch once 15 minutes have passed after its run's execution deadline.

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
| 3b | A bounded worker sweep closes requests the proxy cannot report (`not_dispatched` immediately once undispatchable, `unreported` 15 minutes past the run's execution deadline); migration 32 (delivered 24 November 2026, see the amendment). |
| 3c | A response stopped at its output token limit ends the turn with its partial output, usage and `stop_reason = 'limit'` (dropping partial tool calls); aborted/cut streams map to `Error::Incomplete`; migration 33 (delivered 24 November 2026; see ADR 0036 and ADR 0038). |
| 3e | Proxy cost-hold settlement (issue #166): record immutable `Profile.cost_bound` (`cost_fixed_micros`, `cost_micros_per_token`) on `gateway_requests` at `gateway_handoff_round`, derive `usage_cost_micros` in `quota_gateway_fold` from reported tokens and forbid caller-supplied `cost`/`unit` on unbound requests; migration 34 (delivered 24 November 2026, see the amendment). |
| 3d | Running usage for cut streams. |
| 4 | Family policy tables, SQL evaluator, four-point enforcement, audited store API and `openmettle-admin family` CLI; migration 35 (delivered 24 November 2026, see the amendment). |
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
- **Broad database role.** `openmettle_gateway` still has the grants the reconciler needed. A
  network-facing process needs only the dispatch and settlement functions. Increment 6
  narrows the role.

## Amendment, 24 November 2026: requests that end without usage

Increments 3a (migration 31) and 3b (migration 32). Refs #7.

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
| Nothing was sent upstream | `model_not_served`, `model_mismatch`, `request_body`, `upstream_connect`, `not_dispatched` (sweep-only, revision 0) |
| The request was or may have been sent, and its usage is unknown | `upstream_transport`, `upstream_timeout`, `upstream_status`, `upstream_encoding`, `incomplete`, `caller_disconnected`, `no_usage`, `unparsable`, `unreported` (sweep-only, revision 0) |

**The fold closes the hold.** `quota_gateway_fold` gains one rule: a report that carries a
reason adds no measurement of its own—it carries no usage, cost or unit fields—and settles
the hold at what earlier accepted reports measured (nothing when none carried a
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

**Revisions and worker sweep (increment 3b, migration 32).** The proxy writes its one report
of a request, with usage or without, at revision 1 under the request's own ID. Revision 0 is
owned by the worker's bounded maintenance sweep (`gateway_unreported_candidates` and
`gateway_close_unreported`, `SECURITY DEFINER`, `openmettle_worker` only):

- **Never dispatched (`dispatched_at IS NULL` -> `not_dispatched`, Group 1).** Closed with no
  grace delay as soon as `gateway_dispatch` can no longer grant it under `runs FOR SHARE` ->
  `gateway_requests FOR UPDATE` (run not `running`, `cancel_reason` set, claim mismatch or
  null, or lease/execution deadline passed). A `not_dispatched` report is allowed only at
  revision 0 on an undispatched unbound request with no other accepted revision, and
  `gateway_dispatch` refuses any settled request.
- **Dispatched and unreported (`dispatched_at IS NOT NULL` -> `unreported`, Group 2).** Closed
  15 minutes past the run's execution deadline (preserving `run_approvals.resume_execution_expires_at`
  when a run parked on approval), even if the run finished earlier, giving the proxy its full
  upstream abort and write-retry budget. Settlement lets a higher final revision correct a
  lower one, so a late proxy report at revision 1 (with usage or a proxy reason) supersedes
  the sweep's revision-0 `unreported` record, and the sweep never overwrites revision 1.
- **Role boundary and lock order.** A `BEFORE INSERT OR UPDATE` trigger on
  `gateway_usage_reports` restricts `not_dispatched`, `unreported`, and revision 0 on unbound
  requests to `openmettle_owner` (including the sweep function) so `openmettle_gateway` cannot
  emit sweep reasons or occupy revision 0 to block the sweep, while bound ADR 0037 rows keep
  revision 0 available. Each closed request commits in its own short transaction (`runs FOR
  SHARE SKIP LOCKED` -> `gateway_requests FOR UPDATE SKIP LOCKED` -> `quota_reservations` ->
  `quota_budgets`). Candidate discovery materializes at most `p_limit` raw index entries per
  page and returns each key with its `eligible` flag so the worker advances its pass cursor
  across in-grace or live prefixes under a fixed per-pass upper bound without unbounded index
  scans or head-of-line starvation. Bound ADR 0037 rows are untouched.

**No bare final report.** Settlement and a deferred database trigger refuse any final report on
a request without a binding that lacks both an `incomplete` reason and complete prompt and
completion counts (even when correcting an earlier `unreported` settlement), or that fails to
fold every quota hold on the request to `latest.revision`. The proxy builds a report without
counts only together with its reason.

### Who closes what

| End of the request | After increment 3b |
| --- | --- |
| Completed 200 with usage | The proxy reports the usage at revision 1, as before. This includes a response stopped at its token limit: the recorded server stops at exactly the requested `max_completion_tokens` and still reports usage (observed 24 November 2026). |
| Dispatch spent, nothing sent, or sent and no usage (the twelve proxy reasons) | The proxy writes the incomplete report at revision 1 at once, also when its caller has gone. |
| Never dispatched: the worker did not reach the proxy, or the proxy refused the bearer | The worker maintenance sweep closes it as `not_dispatched` (Group 1) at revision 0 once the run can no longer dispatch it. |
| Dispatch recorded but unconfirmed (`dispatch_unconfirmed`), report write failed (`gateway.usage.failed`), or proxy stopped mid-relay | The worker maintenance sweep closes it as `unreported` (Group 2) at revision 0 once 15 minutes have passed after the run's execution deadline; a late proxy report at revision 1 still supersedes it. |

There is still no local spool: when the database is unavailable the proxy logs the failure,
and the worker sweep reconciles any request left without a report after its grace window.

### Evidence

- `tests/schema/gateway_proxy.rs`: every proxy reason through the binary, among them the
  recorded aborted stream and the recorded 500; metered token and cost holds settled by the
  worker sweep (`not_dispatched` and `unreported`), late complete and incomplete revision-1
  proxy reports superseding revision-0 `unreported`, `dispatch_unconfirmed` closed after grace,
  head-of-line non-starvation across bounded pages, and zero accounting drift.
- `tests/schema/gateway_rounds.rs`: unmetered eligibility across all run states (including
  parked approval waits), concurrent `gateway_dispatch` vs sweep races, bound ADR 0037
  exemption, role/isolation/trigger guards, and upgrades from schema 30 -> 31 and 31 -> 32.
- `tests/schema/live_turns/worker_gateway.rs`: the packaged worker's round refused by a proxy
  serving another model is closed with `model_not_served`; an unreachable proxy fails the turn
  and the packaged worker's own maintenance sweep closes the hold as `not_dispatched`; a
  recorded `07-chat-stream-length` token-limit stop settles at actual usage (`21 + 12`),
  publishes partial text with `message_turns.stop_reason = 'limit'`, and exposes
  `"stop_reason": "limit"` over `GET /v1/conversations/{id}/branches/{branch_id}/messages`.

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
  hold with `model_not_served`; an unreachable proxy fails the turn and the packaged worker's
  maintenance sweep closes the hold with `not_dispatched`.
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

## Amendment, 24 November 2026: cost-hold settlement from recorded profile pricing

Migration 34. Refs #7, #17, #166.

### Problem

`openmettle-gateway` is the only usage witness on binding-free rounds, holds no model catalog
file, and writes `cost = NULL, unit = NULL` on every usage report. Before migration 34,
`openmettle.quota_gateway_fold` settled `usage_cost_micros` holds strictly from
`ceil(step.cost)`, so a complete proxy usage report settled `usage_tokens` while leaving any
`usage_cost_micros` hold stuck in `handoff_committed` indefinitely (issue #166).

### Decision

Instead of duplicating catalog pricing into `openmettle-gateway`, record the immutable
`Profile.cost_bound` on `openmettle.gateway_requests` when the worker hands off a binding-free
round and compute `usage_cost_micros` inside PostgreSQL's `quota_gateway_fold`:

- **Admission-pinned and recorded pricing.** `ConfigSnapshot` pins the model profile's optional
  `cost_bound` (`fixed_micros`, `micros_per_token`) inside `openmettle.runs.config_snapshot` at
  admission (`openmettle_api` only; `openmettle_worker` has no write grant on `runs.config_snapshot`).
  Migration 34 adds nullable `cost_fixed_micros bigint` and `cost_micros_per_token bigint` to
  `openmettle.gateway_requests` (`gateway_requests_cost_bound_check`: both null or both non-null,
  only on unbound handed-off rows, both `>= 0` and at least one `> 0`), with no new table or
  column grants, plus the internal `openmettle.gateway_snapshot_cost_bound(text)` parser
  (validating canonical base-10 integer tokens on raw JSON before `jsonb` normalization).
  `gateway_round_authority` rejects malformed snapshot `cost_bound` values; the 6-arg overload
  `openmettle.gateway_handoff_round(request, dispatch, lease, bearer_hash, cost_fixed_micros, cost_micros_per_token)`
  (`openmettle_worker` only) validates BOTH coefficients individually against the locked run's
  `config_snapshot` before recording `PreparedRequest::cost_bound()` alongside handoff (so a
  worker cannot substitute an alternate `(fixed, rate)` split with the same ceiling). The 4-arg
  overload delegates with `(NULL, NULL)` for draining token-only workers and tests.
- **Handoff and drift invariants.** `enforce_gateway_handoff_holds()` verifies for every unbound
  round that `(NEW.cost_fixed_micros, NEW.cost_micros_per_token)` matches the run snapshot's
  `cost_bound`, requires non-null recorded pricing whenever a `usage_cost_micros` hold is required
  or bound, and verifies `qr.reserved_units::numeric = NEW.units::numeric * NEW.cost_micros_per_token + NEW.cost_fixed_micros`
  (raising `OMQ04` otherwise, while permitting large `cost_bound` values on token-only
  deployments without `bigint` overflow). `quota_recover_lost_handoff` and
  `quota_verify_accounting_drift` enforce the same consistency check while preserving pre-34
  settled history. `resolve_cost_from_state` fails closed if a profile lacking `cost_bound`
  attempts to slice an existing run cost hold even after cost limits expire.
- **Cost fold from reported tokens.** On unbound requests with recorded prices
  (`binding_id IS NULL AND cost_fixed_micros IS NOT NULL`), `quota_gateway_fold` folds token
  counts with the exact `usage_tokens` rules and derives
  `measured = tokens * cost_micros_per_token + cost_fixed_micros` (failing closed with `23514`
  if `measured >= 1e38`). Incomplete and swept reports keep `measured = NULL` so they settle
  at `0` (or prior accepted usage), never `cost_fixed_micros`, while a late revision-1 complete
  report superseding revision-0 `unreported` charges the derived cost. Bound ADR 0037 rows and
  pre-34 rows without recorded prices retain `ceil(step.cost)` and migration 31's historical fold
  transitions (preserving zero drift across `33 -> 34` even if a schema-33 `unreported` sweep was
  followed by a token-only report before upgrade), while `enforce_gateway_final_settlement_closes()`
  refuses (`23514` / `Error::Refused`) any newly accepted count-bearing settlement on an unpriced
  (`cost_fixed_micros IS NULL`) cost-held unbound request; an operator can reconcile such a legacy
  request via the owner-only
  `openmettle.gateway_backfill_legacy_request_cost_bound(request, fixed_micros, micros_per_token)`
  function (which stamps pricing and reconciles any already-accepted token-only usage against the
  cost hold and budgets).
- **No caller-supplied cost or undispatched settlement on unbound requests.** Both
  `settlement::ingest` (after exact historical replay recognition) and a `BEFORE INSERT OR UPDATE`
  trigger (`gateway_usage_reports_bound_cost_guard` -> `enforce_gateway_report_bound_cost`, no
  role bypass including `openmettle_owner`) refuse non-null `cost` or `unit` on unbound requests
  (`23514`), while bound ADR 0037 requests continue to accept them. Migration 34 also removes any
  unaccepted historical raw unbound usage reports carrying `cost`/`unit`, and widens the deferred
  `gateway_final_settlement_closes` trigger to fire on BOTH final and non-final settlements so
  `enforce_gateway_final_settlement_closes()` blocks direct `openmettle_gateway` SQL from
  settling an undispatched unbound request (other than the revision-0 `not_dispatched` sweep) or
  newly accepting a cost/unit-bearing report on an unbound request.
- **No `#166` carve-out at commit.** `enforce_gateway_final_settlement_closes()` now requires
  every bound hold (`usage_tokens` and `usage_cost_micros`) on an unbound final settlement to
  have folded `latest.revision` and reached `state = 'settled'`, running the `usage_cost_micros`
  fold iff a `usage_cost_micros` hold exists on the request (so large unused `cost_bound` values
  never reject token-only settlement).
- **Fail-closed upgrade preflight without lock-order deadlock.** Inside an autocommit-safe `DO`
  block acquiring `ACCESS EXCLUSIVE` on `gateway_requests`, `gateway_usage_reports` and
  `gateway_settlements` and `SHARE` on `quota_reservations` via a bounded `NOWAIT` retry loop
  (rolling back subtransactions on `lock_not_available` so concurrent schema-33 report writers
  never deadlock on the FK lock order), migration 34 refuses (`23514`) if any unbound request
  still carries an unsettled `usage_cost_micros` hold (`state IN ('held', 'handoff_committed')`),
  preserving all already-settled historical rows.

### Evidence

- `tests/schema/gateway_proxy.rs`: real `openmettle-gateway` binary settling `02-chat-plain`
  and `04-chat-stream-reasoning` cost holds across personal, project and instance budgets from
  recorded `(fixed_micros, micros_per_token)` pricing; `UPSTREAM_500`, `not_dispatched` and
  `unreported` settling at `0` (not `fixed_micros`); late revision-1 correction charging the
  derived cost; caller-supplied `cost`/`unit` refused via `settlement::ingest`,
  `openmettle_gateway` and `openmettle_owner` SQL; direct SQL skipping the fold refused at
  commit.
- `tests/schema/live_turns/worker_gateway.rs`: packaged `openmettle-worker` +
  `openmettle-gateway` end-to-end cost-metered 2-round run recording `Profile.cost_bound` at
  handoff, settling Round 1 tokens and cost through the proxy, unwinding unused Round 2 parent
  holds at completion, and reporting zero accounting drift.
- `tests/schema/gateway_rounds.rs` and `tests/schema/grants.rs`: `33 -> 34` upgrade preflight
  refusal and historical replay preservation, `measured >= 1e38` overflow refusal, bound
  ADR 0037 cost acceptance, `OMQ04` pricing mismatch refusal, expired-limit unqualified refusal,
  and column/function grant boundaries.

## Amendment, 24 November 2026: family policy tables and enforcement

Increment 4 (migration 35). Refs #7.

### Problem

With third-party gateway provisioning removed, quiet hours, study hours and per-model switches
had no durable schema, no authoritative evaluator and no enforcement at admission, worker
execution, handoff or proxy dispatch.

### Decision

- **Current-state policy tables (no `DELETE` grants).** Migration 35 adds
  `openmettle.family_policies` (keyed by `(grantee_kind, grantee_user_id, grantee_local_group_id,
  grantee_oidc_group_id)` with `UNIQUE NULLS NOT DISTINCT`, IANA `zone` validated against
  `pg_catalog.pg_timezone_names`, optional half-open minute windows for `quiet` and `study` with
  midnight wraparound, user-only `override_group_schedules`, `active` and strictly increasing
  `revision`) and `openmettle.family_policy_models` (`(policy_id, rule_kind, model)` for
  `'study_allow'` and `'disabled'` rules, `active` and monotonic `revision`). `openmettle_api`
  receives `SELECT` and column-scoped `INSERT`/`UPDATE` only (triggers reject null
  `updated_by_user_id` for non-owners, unknown timezones and non-increasing revisions);
  `openmettle_worker`, `openmettle_gateway`, `openmettle_issuance` and `PUBLIC` hold no table
  grants. `openmettle.authorization_audit` CHECK constraints widen additively under a bounded
  `NOWAIT` retry loop for `'family_policy.set'`, `'family_policy.clear'`,
  `'family_policy.model_study_allow'`, `'family_policy.model_study_revoke'`,
  `'family_policy.model_disable'` and `'family_policy.model_enable'`.
- **Single authoritative SQL evaluator.** `openmettle.family_policy_filter_models(p_user,
  p_approval, p_models, p_at)` (`STABLE`, `SECURITY DEFINER`, `SET search_path = pg_catalog`,
  granted to `openmettle_api`) and its single-model wrapper `openmettle.family_policy_permits(
  p_user, p_approval, p_model, p_at)` (granted to `openmettle_api` and `openmettle_worker`)
  evaluate all applicable active policies (`user`, active enabled `local_group` memberships,
  and fresh `'present'` `oidc_group` observations). An active user row with
  `override_group_schedules = true` evaluates only that row. Otherwise, any
  `membership_observations` row on `(p_approval, p_user)` whose enrolled mapping revision
  (`mo.rule_id, mo.rule_revision`) OR latest mapping revision (`r.id, r.last_revision`) targets
  an active `oidc_group` family policy fails closed (`false`) whenever the observation is
  disabled (`NOT mo.enabled`), superseded or disabled at its mapping revision, expired/stale,
  missing, partial, ambiguous, failed or mismatched in epoch, generation or `grant_changes`
  (leaving confirmed fresh `'absent'` and genuinely unenrolled users unaffected). Each
  applicable policy converts `p_at` once via PostgreSQL's in-memory `AT TIME ZONE` cache
  (zones are validated against `pg_catalog.pg_timezone_names` on write; no per-call filesystem
  scan) so spring-forward missing minutes never occur and both autumn fall-back occurrences
  agree, then evaluates `quiet`, `disabled` and `study`/`study_allow` in order.
- **Four enforcement points (catalog routes unchanged).** `GET /v1/models`, `GET /v1/presets`,
  `GET /v1/presets/{preset_id}` and `check_project_defaults` remain unchanged:
  1. *API admission & effective-configuration preview* (`src/v1/submission.rs`,
     `src/model_config.rs`): resolves model/preset/capabilities first (`400 validation` on
     missing project default or invalid input; `403 policy` without fallback on capability-denied
     defaults), checks the resolved model via `family_policy_permits`, and batch-evaluates the
     catalog via `family_policy_filter_models` only when an omitted selection's
     capability-allowed project default is rejected by family policy (auto-skipping to the first
     deterministic model permitted by both capabilities and family policy, or `403 policy` if
     none is permitted). Exact idempotent replay (`Admission::Replayed`) stays `200 OK` during
     quiet hours.
  2. *Worker claim, step recheck & turn handoff* (`src/authz/runs.rs`, `src/worker/turns.rs`):
     `recheck_run` validates `runs.actor_approval_id` when recorded; `recheck_step` evaluates
     both `recheck_claim` and `recheck_leased` at post-fence `clock_timestamp()`;
     `recheck_decision` decodes full `ConfigSnapshot` for `openmettle.conversation` v1 snapshots
     (failing closed on malformed v1 snapshots; skipping non-conversation synthetic runs) and
     invalidates with `PolicyReason::FamilyPolicy` (`cancel_reason = 'revoked'`); and
     `TurnExecutor` rechecks authority after a refused `handoff_turn` so family denial first
     observed at handoff settles as `revoked` rather than `step_failed`.
  3. *PostgreSQL handoff & confirm* (`gateway_round_authority`, `gateway_handoff_round`):
     `gateway_round_authority` adds `family_policy_permits`, while `gateway_handoff_round` keeps
     the canonical handoff lock prefix (`account_admin_lock FOR SHARE -> projects ->
     login_providers/approvals -> users -> runs -> gateway_reservations -> gateway_requests`);
     both `Action::ManageLocalGroups` and `Action::ManageFamilyPolicies` (plus
     `openmettle-admin family`) acquire `account_admin_lock FOR UPDATE`, serializing local-group
     membership and policy changes with handoff without lock-order inversions.
  4. *PostgreSQL proxy dispatch* (`gateway_dispatch`): after proving the bearer, acquires the
     canonical shared authorization prefix (`account_admin_lock -> login_providers/approvals ->
     users -> runs -> gateway_requests`) and checks `family_policy_permits` inside its
     `UPDATE ... WHERE` clause so concurrent policy/group writes, approval withdrawals and user
     disables serialize before spending the bearer (`401`, nothing sent upstream; wrong bearers
     still take zero locks; worker sweep closes as `not_dispatched` at `0`).
- **Audited administration.** `Action::ManageFamilyPolicies` (active `account_admin`,
  serialized under `account_admin_lock FOR UPDATE -> login_providers/approvals FOR SHARE ->
  users(actor) FOR SHARE` via shared `store::write`) exposes
  `store::{set_family_policy, clear_family_policy, set_family_policy_model, load_family_policy}`
  as `openmettle_api` (`actor_kind = 'user'`). `openmettle-admin family` (`set-policy`,
  `clear-policy`, `set-model`) connects via `OPENMETTLE_ADMIN_DATABASE_URL` (`openmettle_owner`),
  acquires `account_admin_lock FOR UPDATE` and records `'operator'` audit rows.

### Evidence

- `tests/schema/family_policy.rs`: DST spring-forward and both autumn fall-back occurrences in
  `Europe/London` and `America/New_York`, OIDC `Family` group inheritance and fail-closed across
  all stale/missing/partial/ambiguous/failed/expired/generation states, `override_group_schedules`
  exemption, HTTP `/v1/runs` and `effective-configuration` quiet-hours `403 policy` + replay +
  study-hours fallback + unfiltered `/v1/models` and `/v1/presets`, worker `recheck_run` /
  `recheck_leased` cancellation, `gateway_handoff_round` / `gateway_handoff_round_confirm` /
  `gateway_dispatch` refusal + `not_dispatched` sweep, `ManageFamilyPolicies` store authz/audit
  and disable serialization, `openmettle-admin family` CLI e2e, role/trigger boundaries, and
  `34 -> 35` upgrade.
- `tests/model_config.rs` and `src/authz/gateway/family.rs`: `Catalog::resolve_with_fallback`,
  strict `HH:MM-HH:MM` window parsing and `openmettle-admin family` argument parsing.
