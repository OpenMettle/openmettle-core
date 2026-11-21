# 0037 — Application-owned gateway provisioning and usage reconciliation

Proposed for Wave 18c, V1-06 PR1, 21 November 2026. Refs #7. This design depends on
V1-04 identity admission and V1-05 authorization. Implementation and gateway qualification
follow in separate increments. [Delivery contract](https://github.com/OpenMettle/openmettle-core/issues/7).

## Authority and admission

OpenMettle supplies the admitted actor and effective grants to the selected gateway
(initially LiteLLM with the existing gateway boundary). The gateway owns virtual keys,
inference budgets, family schedules and authoritative usage. PostgreSQL records the
application's intent, the gateway's confirmed state and the requests awaiting settlement.
Family/Parents onboarding uses the OpenMettle user UUID and approved group mapping.
It needs no Open WebUI account, forwarded user header or upstream login token.
[Architecture baseline](../../ARCHITECTURE-v1.md#identity-privacy-and-configuration)
and [gateway boundary source pin](../../SOURCE-REFERENCES.md#s01).

The requirement `users.approval_status = 'approved'` maps to existing authority rows.
On the primary, verify that the **exact** `local_identity_approvals` row belongs to the
user's identity and is active and unexpired at database time. Require a current provider
and `users.disabled_at IS NULL`. Rehydrate current
grants, mapped membership evidence and platform/user denies under ADR 0027. Pending,
rejected, withdrawn, expired or disabled identities cannot create a principal, budget or
key. Successful OIDC verification, a pending invitation and an account-admin role each
confer no inference entitlement. Start onboarding only after admission commits.
[Managed login](0011-managed-provider-keys.md) and [authorization](0027-authorization-and-private-projects.md).

One gateway principal per (gateway installation, user) has one stable budget binding across
renewals and rotations. Pin the exact approval and grant cycles used for each authorized
request. Keep project and capability checks scoped to that request, including when the
user has another linked identity. Virtual keys stay server-side. For
client-owned completions the API sends a short-lived, audience-bound service authorization
for the checked actor, scope and request. The gateway resolves the principal internally.
The application maps effective grants to allowed models and capabilities. The gateway
intersects them with the child's configured switches and its
quiet/study schedule at request time. Quiet hours refuse inference. Study hours admit only
the configured study set. A disabled switch or platform/user deny wins over any allow.
Use the gateway's configured family time zone and policy revision. A schedule change takes
effect even during a worker outage. Require this enforcement before enabling the profile.

## Reconcile one principal

Keep desired revision, observed revision, credential generation, expiry and unresolved
operation identity durable. The worker sweeps due or changed bindings in bounded batches,
including newly eligible accounts with no binding. Application grant and policy writers
record a reconciliation request in the change transaction. Expiry and operator changes
are also discovered from current authority by the sweep.
Repeated wakes, sign-ins and replica restarts converge on the same binding. Recheck the
primary before each enabling step, when publishing its result and at inference dispatch.
Use the gateway's observed revision and expiry to establish readiness.

| Trigger and state | Worker transition and condition for use |
| --- | --- |
| First eligible grant, `absent → provisioning` | After endpoint readiness, ensure the stable principal, attach its budget and apply the model/capability and family-policy binding. Issue the first key only against that binding. Read back principal, policy, budget, key handle and expiry before marking the generation `ready`. |
| Grant, family mapping or gateway policy changes, `ready → syncing` | Diff against the current authoritative policy. Apply the current desired revision conditionally, then read it back. Block affected use immediately on a restriction. An added entitlement becomes usable only after confirmation. An identical revision and effective payload require no write. |
| Renewal or rotation, scheduled before expiry or requested on demand, `ready → renewing` | Authorize the request and coalesce triggers for the same change. Renewal may extend the identified key in place. Rotation stages one successor on the **same budget**. Confirm its restrictions and expiry, seal it, then atomically switch the local active reference. Retire the identified predecessor with its own operation and confirm retirement. Bound overlap by the predecessor's expiry. An expired key cannot serve traffic. |
| Disable, approval withdrawal/expiry, or loss of a required grant, any state → `suspended` for the affected authority | The committed change or expiry immediately bars new local use under that authority, even with the worker down. Give remote suspension/restriction priority, including for staged keys. Remove the affected rights. With no remaining eligible authority, disable the principal and revoke all its generations. Mark `revoked` only on gateway confirmation. Re-admission requires fresh authority and a new generation. |
| Outcome unknown or operator intervention required | Keep the intent and every known handle. Withhold readiness for the affected operation. Resolve uncertain effects by lookup. A failed replacement can use its predecessor only while independently confirmed current, permitted and unexpired. Explicit compromise suspends use immediately. |

A committed revocation fences later requests. It cannot recall bytes already sent. Run
workers recheck before each model/tool step and use the existing cancellation and lease
protocol. A delayed success for an old revision is evidence for cleanup only. It cannot
reactivate that revision. Reconcile surviving gateway bindings and usage after restore
with dispatch disabled. [Run admission](0032-durable-run-admission-and-fair-work-queue.md)
and [lease recovery](0033-worker-leases-deadlines-and-restart-recovery.md).

### Mutation identity and recovery

1. Before I/O, insert one intent for the logical step. Enforce uniqueness on gateway
   installation, user, desired revision, target resource/generation and action. Persist a
   server-generated operation key, expected remote revision, exact normalized non-secret
   parameters and any sealed credential reference. Bind the key to that payload. A
   conflicting replay stops. Each create, budget attachment, policy update, renewal,
   rotation, suspension and retirement has its own step. Record completion of a prerequisite
   before starting its dependent step.
2. After checking the live claim and current authority for the step, commit the intent,
   release the database connection and send the persisted key to the pinned admin endpoint.
   The selected adapter must demonstrate durable remote deduplication or a conditional
   write on a unique application-chosen resource ID with authoritative lookup. Bind
   updates and creates to the expected principal revision. Keep a revocation marker even
   for an in-flight create so a stale request cannot recreate a suspended principal.
   A local unique constraint or an echoed request ID alone cannot provide this property.
3. Record the observed handle, revision and outcome under the original key. On a lost
   commit reply, timeout after send, stale worker or restart, inspect that intent and look
   up the remote result first. Resend identical bytes only when the endpoint proves safe
   same-key replay within its deduplication window, or its conditional create/update still
   guarantees a single effect. Keep ambiguity blocked beyond that window. Never mint
   another key or budget to recover a lost reply. Serialize a successor behind unresolved
   writes to the same resource unless the gateway fences them. A separately created budget
   must be uniquely addressable from its committed intent before attachment. Reconcile any partial
   allocation to completion or verified retirement before abandoning the binding.
4. An endpoint that returns a virtual-key secret only once must accept a worker-generated,
   pre-sealed secret or support authenticated recovery of the same issued credential.
   A lookup proving that a key exists alone cannot recover its secret. A profile lacking
   a safe issue/recovery path stays disabled. Apply these requirements to the pinned
   gateway version in wire tests. [Intent and observation precedent](0035-approvals-permitted-yolo-and-effect-ledger.md).

### Process, secret and lock boundaries

| Actor | Access for this design |
| --- | --- |
| `openmettle-api` / `openmettle_api` | Authorize requests and policy changes. Write only authorized desired inputs or a reconciliation request and admission reservation identity. Read scoped, non-secret status and usage projections. No admin endpoint, admin token, wrapping key, ciphertext read or settlement write. |
| `openmettle-worker` / `openmettle_worker` | Read current authority. Permit column-scoped inserts of intents, envelopes, reports and audit observations, and guarded updates of claims, binding state and settlement totals. Run the admin client only in a dedicated reconciliation worker deployment with a gateway credential restricted to its managed principals, keys, budget attachments, policy bindings and usage. Keep that credential out of API, run executors, model/tool contexts and clients. |
| Migrator | Version-gate the additive tables, constraints and column grants in `src/boundaries.sql`. Neither runtime role owns tables or has DDL, grant options or audit deletion rights. Issuance and PUBLIC gain no gateway access. |

PR2 adds gateway key protection through [`src/provider_keys.rs`](../../src/provider_keys.rs).
Today that module manages OIDC verification keys and passes `login::KeyRing` into login
operations. The existing AES-256-GCM envelope and nonce reservation are in
[`src/login.rs`](../../src/login.rs) and [ADR 0009](0009-protected-login-transactions.md).
Reuse that pattern with a separate gateway-only ring and versioned domain. Authenticate
installation, user, principal handle, credential generation, purpose, format and wrapping
key ID as associated data. Reserve a unique 96-bit nonce per wrapping key in an acknowledged
transaction before each seal. Store only the version, key ID, nonce, ciphertext/tag and
non-secret references. Mount wrapping keys separately from PostgreSQL only in workers that
must seal or resolve virtual keys. New writes use the active key. Retain previous keys
until all live envelopes are rewrapped with fresh nonces. After loss of nonce history,
switch wrapping keys before another seal. Missing keys or tag failures block use and raise
an operator error. No plaintext in SQL, snapshots, clients, audit, logs or spans.

Use bounded READ COMMITTED transactions on the primary. Keep the established order
`account_admin_lock → projects → users → runs → branch_heads`, taking only necessary
locks, with ascending IDs within a class. Acquire the gateway binding, its operation and
the request reservation/settlement rows after applicable existing locks, in that order.
Claim due work with a bounded `SKIP LOCKED` transaction, then commit. A subsequent
transaction that needs authority locks starts at the beginning of the order. Append the
remote observation to its original intent, including handles needed for cleanup. Advance
current state only if the claim and desired revision still match. A transaction holding
a gateway row cannot take an earlier lock. Release the pool connection before HTTP.
[Authorization locks](0027-authorization-and-private-projects.md)
and [graph lock order](0036-conversation-branches-presets-and-effective-model-config.md).

### Endpoint readiness and refusal

Use a gateway-specific client over [`provider_http::transport`](../../src/provider_http.rs).
Pin each operation's HTTPS destination, method and trust in deployment configuration. Only
the admin adapter may attach its credential to that destination. The existing OIDC client
refuses caller-supplied authorization headers. Preserve address validation for every DNS
answer, private-range opt-in, TLS verification, response framing/size caps and cancellation.
Use a dedicated bounded DNS pool, a 5-second setup and 10-second total ceiling per call,
and a finite batch deadline covering readiness and backoff. Probe the configured endpoint
before mutation. No redirects, proxies or transport retries. After transient connectivity
failure, defer to a later bounded sweep with backoff and jitter. Policy and HTTP 4xx
refusals stop automatic retries until the relevant inputs change or an operator repairs
the cause. Failed readiness or gateway admission stops every dependent destructive step,
including retiring a working predecessor. [Transport contract](0010-provider-http-transport.md).

| Evidence | Application response and operator evidence |
| --- | --- |
| Inactive caller or hidden target | Apply ADR 0027 first. Return `401 unauthenticated` or concealed `404 not_found`. Do not probe another account. |
| Admitted caller, visible target, known missing model grant or family restriction | `403 policy`. Give the caller the applicable action, such as “Ask your account administrator to enable model access” or “Try again after quiet hours.” |
| Admitted, entitled caller whose account binding is confirmed absent or awaiting initial sync | `503 provisioning`. “Gateway access for your account is being set up. If this persists, contact your account administrator.” Check this before default model selection to prevent `Model '' was not found` (#254). |
| Service credential refused on the admin endpoint (including 401/403), endpoint unreachable, or unverified gateway response | `503 unavailable` for affected requests. “Gateway access is unavailable. Contact the operator with the request ID.” Record the failed step and cause. This failure takes precedence over an incomplete binding. An unexplained upstream 401/403 supplies no evidence of missing user entitlement. |

Retain #255 (identify the failed step), #258 (stop the transition) and #259 (bounded
readiness) from the [delivery index](https://github.com/OpenMettle/openmettle-core/issues/1).
Use the existing [application problem codes](0007-application-api-contract.md). Record
restricted append-only audit rows with the internal binding/operation reference, desired
revision, timestamp, step and outcome. For telemetry use the closed step vocabulary
`readiness`, `principal`, `budget`, `policy`, `key`, `revoke` and `usage`. Classify causes
as `policy`, `service_auth`, `transport`, `timeout`, `protocol`, `protection` or `unknown`.
Use aggregate counts and fixed lag buckets. Register any new events, fields and series
ceilings in the versioned contract before emission. Keep IDs out of metric labels and
gateway handles, tokens, URLs, headers, bodies, prompts and child policy details out of
telemetry. [Redaction](0024-process-telemetry-and-redaction.md) and
[bounded metrics](0028-telemetry-contract-and-metrics.md).

## Request reservations and measured usage

At admission, bind the reservation to the ADR 0032 run, actor and accounting scope in
the same transaction. Exact admission replay reuses it. Before each billable call, persist
a distinct request identity (including the round) against that reservation and pass it
through the gateway. Allocate each call its own portion of the run hold before send.
Moving a portion to a request leaves the total held unchanged. Release unallocated units
when no further calls can start. A client-owned completion without a run uses the same
authorized request/reservation binding. One run can incur several charges. Never join by time,
model name or the user's current key. Keep attribution across key rotation and revocation.

For each request designate one authoritative gateway/provider reporting source through the
qualified profile. Bind its request handle to the original installation, principal, scope
and request. Authenticate the feed. Normalize reports to cumulative measurements with
source report ID, a revision ordered within the request, and finality. Record nullable,
nonnegative `prompt_tokens`, `completion_tokens`, `reasoning_tokens` and exact cost/currency or credits/unit when
reported. Preserve the profile's definition of reasoning included in completion so it
cannot be added twice. Absent fields stay unknown. Reject foreign bindings, invalid units
and unorderable corrections for investigation. A gateway forwarding a provider report
does not create a second charge.

| Observation | Settlement on the primary |
| --- | --- |
| Duplicate or out of order | In one transaction lock the request reservation, deduplicate (source, report ID, revision), advance the accepted request revision and apply only the difference from its previous cumulative amounts. An exact duplicate or older revision changes no balance. Different values at the same request revision are quarantined. Require an authoritative higher revision for a correction, including a decrease. A late partial cannot reopen a final report. |
| Partial or final report | Move confirmed units from outstanding to measured. For a 100-token hold and 30 confirmed so far, count 30 measured and 70 held. A final total of 45 adds 15 and releases 55, once. Record actual overage in full. Settle reported units independently and hold any still-unresolved reserved unit. |
| Cancelled, failed or interrupted run | Proven unsent or authoritative no-charge releases the unused hold once. After possible dispatch, settle confirmed partial usage and retain the unresolved remainder pending a final report or proof of no further charge. A terminal run, expired lease, timeout or missing report cannot prove zero usage. Late evidence settles the original request without reopening the run. |
| Missing or delayed evidence | Store last successful reconciliation time, report cursor and oldest unresolved request. Backfill by request handle across overlapping pages. Commit cursor progress with accepted reports or durable exceptions. Bound each pass and flag overdue holds for operator lookup. Preserve outstanding exposure and report its age until resolved. |

ADR 0036's immutable assistant `message_turns.input_count` and `output_count` may record
measured prompt/completion counts **for the final model call** available at publication.
Unknown stays null. Later reports update request settlement only. Never sum a turn
projection or a context estimate into the ledger, manufacture a turn for a failed run, or
overwrite an earlier branch's measurement. V1-06 supplies idempotent measured deltas and
remaining holds. V1-17 owns transactional user/project quota reservation, limits and their
atomic consumption/release. Keep the gateway authoritative for inference billing and
enforcement. [Conversation measurements](0036-conversation-branches-presets-and-effective-model-config.md)
and [quota contract](https://github.com/OpenMettle/openmettle-core/issues/17).

## Delivery and verification

| Slice | Required evidence |
| --- | --- |
| PR1 · design | This decision and the forward pointer in ADR 0011. Review against #7 and the four historical failures. Run repository hygiene and offline application contract fixtures. |
| PR2 · additive schema and store | Fresh and populated PostgreSQL 18 upgrade, previous writer compatibility, scoped FKs, unique principal/budget/key and operation identity. Race duplicate intents and stale generations. Assert role-specific SQL grants and refusals, including API ciphertext denial. Test nonce collisions, wrong binding/tag, wrapping-key rollover and missing keys. |
| PR2 · gateway admin client | Synthetic TLS fixture counts wire requests. Exercise refused addresses, redirects, TLS, stalled readiness, 4xx and response limits. Drop the reply after committing each create. Restart and recover the original budget/key and usable sealed secret. Verify zero extra creates, zero dependent destructive calls and no secret in diagnostics. |
| PR3 · reconciliation sweep and error mapping | Race workers, renewal and disable/withdrawal. Exercise approved, pending, rejected, expired and disabled identities, grant loss, schedule boundaries and per-child switches. Assert immediate local refusal, remote convergence, bounded lag, unchanged budget on rotation and no stale reactivation. Drive the four regression cases through the caller and verify status, action, failed step and redaction. |
| PR3 · usage settlement | On PostgreSQL 18 race duplicate reports with cancellation and crash after commit. Deliver final before partial, corrected final, partial/unknown usage, delayed backfill and confirmed no-charge. Assert exact measured/held totals, cross-scope refusal, no duplicate debit, independent multi-round and final-turn counts, and identical results after restart. |

PR2 takes the next available additive migration after coordination with concurrent tracks.
PR3 exercises the worker and settlement against synthetic gateway evidence. Enabling a
selected gateway requires evidence for its pinned admin, family-policy and reporting
contracts. Those gates and V1-17 quota enforcement remain open after PR1.
