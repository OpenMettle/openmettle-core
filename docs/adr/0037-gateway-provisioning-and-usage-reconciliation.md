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

`openmettle.users` has five columns (`id`, `created_at`, `disabled_at`,
`session_generation`, `lock_guard`) and no `approval_status` column. On the primary,
verify that the exact `local_identity_approvals` row belongs to the user's identity,
is active and is unexpired at database time. Require a current provider and
`users.disabled_at IS NULL`. Rehydrate grants, mapped membership evidence and
platform/user denies for that approval and request under ADR 0027.

Use live schema states in admission tests. “Pending” means an unredeemed
`home_invitations` row with `approval_id IS NULL`, `withdrawn_at IS NULL` and no
matching approval. Exercise “rejected” with a withdrawn invitation
(`approval_id IS NULL`, `withdrawn_at IS NOT NULL`) and with an existing
`local_identity_approvals.active = false`. Also exercise an absent approval, an expired
approval and a disabled user (`users.disabled_at IS NOT NULL`). None authorizes
provisioning under that identity. OIDC verification or account administration alone
confers no inference entitlement. Start onboarding only after admission commits.
[Managed login](0011-managed-provider-keys.md) and [authorization](0027-authorization-and-private-projects.md).

One gateway principal per (gateway installation, user) keeps one budget binding across
renewals and rotations. Both inference callers send that user's virtual key as the bearer
on the pinned inference route. For a caller-owned completion, the API derives the actor
from the validated session. For each server-owned run round, the run worker derives the
actor from the admitted run and rechecks its live lease. Both resolve the credential at
dispatch for the exact approval, grant cycles, scope and model, including when the user
has another linked identity. The key stays server-side.
[Inference adapter (ADR 0038)](https://github.com/OpenMettle/openmettle-core/pull/118).

The application maps effective grants to allowed models and capabilities. The gateway
intersects them with the child's configured switches and its
quiet/study schedule at request time. Quiet hours refuse inference. Study hours admit only
the configured study set. A disabled switch or platform/user deny wins over any allow.
Use the gateway's configured family time zone and policy revision. A schedule change takes
effect even during a worker outage. Require this enforcement before enabling the profile.

## Reconcile one principal

Keep desired revision, observed revision, credential generation, expiry and unresolved
operation identity durable. The dedicated reconciliation worker (`openmettle_gateway`)
sweeps due or changed bindings in bounded batches, including newly eligible accounts
without a binding. API-layer grant and policy writers record a reconciliation hint in the
change transaction, outside `grants::change_grant`. OIDC membership sync calls that same
grant writer as `openmettle_issuance`. The scheduled sweep discovers issuance-time mapped
membership changes and newly redeemed invitations, as well as expiry and operator changes.
Issuance needs no gateway privileges. [Membership sync](../../src/membership.rs) and
[issuance boundary](0030-session-issuance-database-boundary.md).

Repeated wakes, sign-ins and replica restarts converge on the same binding. Recheck the
primary before each enabling step, when publishing its result and at inference dispatch.
Use the gateway's observed revision and expiry to establish readiness.

| Trigger and binding state | Reconciliation worker action and condition for use |
| --- | --- |
| First eligible grant, `absent → provisioning` | After endpoint readiness, ensure the stable principal, attach its budget and apply the model/capability and family-policy binding. Issue the first key only against that binding. Read back principal, policy, budget, key handle and expiry before marking the generation `ready`. |
| Grant, family mapping or gateway policy changes | Diff against the current authoritative policy. Apply the current desired revision conditionally, then read it back. Block affected use immediately on a restriction. An added entitlement becomes usable only after confirmation. An identical revision and effective payload require no write. |
| Renewal or rotation of a `ready` generation, before expiry or on demand | Authorize the request and coalesce triggers for the same change. Renewal may extend the identified key in place. Rotation stages one successor on the **same budget**. Confirm its restrictions and expiry, seal it, then atomically switch the local active reference. Retire the identified predecessor with its own operation and confirm retirement. Bound overlap by the predecessor's expiry. An expired key cannot serve traffic. |
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

| Process and PostgreSQL role | Gateway privileges and credential mounts |
| --- | --- |
| Caller-owned completions · `openmettle-api` / `openmettle_api` | Authorize desired inputs, write API reconciliation hints and create the caller's reservation. Insert the per-call request identity before send. Execute the scoped lookup and proven-unsent release. Mount `gateway_keys` for unseal only. Read scoped status and usage projections. |
| Server-owned runs · `openmettle-worker` / `openmettle_worker` | Insert the per-round request identity against the run reservation before send. Execute the same lookup and proven-unsent release for the leased run. Mount `gateway_keys` for unseal only. |
| Dedicated reconciliation and settlement process · `openmettle_gateway` | Read current authority on the primary. Reserve nonces and append audit observations with `INSERT` only. Sole runtime role with column-scoped `INSERT` and guarded `UPDATE` on gateway admin intents and claims, sealed virtual-key envelopes, `gateway_bindings` lifecycle state (`provisioning`, `ready`, `suspended`, `revoked`), usage reports and settled totals. Only this process holds the outbound gateway admin service credential and mounts `gateway_keys` for both seal and unseal. Limit the credential to managed principals, keys, budget attachments, policy bindings and usage. |
| Migrator | Own the lookup and version-gate the new role, tables, grants and function privileges in `src/boundaries.sql`. Require disjoint runtime logins, with no ownership, DDL or grant options, following [ADR 0030](0030-session-issuance-database-boundary.md) and [migration 18](../../migrations/0018_session_issuance_role.sql). Revoke default function execution from `PUBLIC`. Grant no gateway access to `PUBLIC` or `openmettle_issuance`. |

Both inference roles have zero direct `SELECT` on the raw envelope table or ciphertext
column and zero `INSERT` or `UPDATE` on binding state or settled usage. Neither receives
the admin credential. Grant them `EXECUTE` on one migration-owned `SECURITY DEFINER`
envelope lookup with `SET search_path = pg_catalog` and schema-qualified relations.
Bind the lookup to one pre-send request and reservation. For the API, verify possession
of the live session credential. For the run worker, verify the current fenced lease for
that round. Derive `actor_user_id` from the session or run and require the request's
actor, scope and exact approval to match. Recheck current authority for the requested model and
capability. Return at most that actor's active envelope and its authenticated metadata,
only for `gateway_bindings.state = 'ready'`, a confirmed applicable policy revision and
an unexpired generation. A supplied user ID alone cannot authorize lookup. Provide no
enumeration or batch lookup.

PR2 adds gateway key protection through [provider keys](../../src/provider_keys.rs).
Reuse the AES-256-GCM envelope and nonce reservation pattern from login in a separate
versioned domain. Bind the associated data (AAD) to `(user_id, binding_id, key_generation)`,
installation, principal handle, purpose, format and wrapping key ID.
Before sealing, the reconciliation worker commits a unique 96-bit nonce reservation
under the active wrapping key. Store only the version, key ID, nonce, ciphertext/tag
and non-secret references. At dispatch, unseal into a `Zeroizing` buffer, construct one
internal bearer `Authorization` header with `HeaderValue::set_sensitive(true)` and drop the buffer as
soon as the header is built. Keep plaintext out of SQL, snapshots, clients, audit, logs
and spans. [Login envelope](../../src/login.rs) and [ADR 0009](0009-protected-login-transactions.md).

PR2 extends offline configuration validation to `gateway_keys`. Store each key as
exactly 32 raw bytes in a mounted file referenced by absolute path. Environment
variables cannot supply key material. Allow one active generation and up to three
previous keys for unseal. Inference processes expose only the unseal operation and have
no nonce allocation grant. Reject duplicate IDs or material within the ring. In the
offline deployment check, compare every gateway key with every configured login,
cursor and BYOK/connector key using `subtle::ConstantTimeEq`. Reject shared material
before rollout without mounting unrelated rings in the reconciliation worker. Rewrap
live envelopes with fresh nonces before retiring old keys. Rotate the wrapping key after
loss of nonce history and before another seal. A missing key or failed tag blocks use
and raises an operator error. [Offline configuration checks](0015-offline-auth-config-check.md).

Use bounded READ COMMITTED transactions on the primary. Keep the established order
`account_admin_lock → projects → users → runs → branch_heads`, taking only necessary
locks, with ascending IDs within a class. PostgreSQL requires an `UPDATE` privilege
for `FOR SHARE` and `FOR NO KEY UPDATE`. Where the reconciliation worker locks an
authority row, grant `openmettle_gateway` only `UPDATE (lock_guard)` for that lock and
record the grant in `src/boundaries.sql`. Acquire the gateway binding, its operation and
the request reservation/settlement rows after applicable existing locks, in that order.
Claim due work with a bounded `SKIP LOCKED` transaction, then commit. A subsequent
transaction that needs authority locks starts at the beginning of the order. Append the
remote observation to its original intent, including handles needed for cleanup. Advance
current state only if the claim and desired revision still match. A transaction holding
a gateway row cannot take an earlier lock. Release the pool connection before HTTP.
[Authorization locks](0027-authorization-and-private-projects.md)
and [graph lock order](0036-conversation-branches-presets-and-effective-model-config.md).

### Endpoint readiness and refusal

Use a gateway-specific client over the [bounded HTTP transport](../../src/provider_http/transport.rs).
Pin the HTTPS destination, method and trust for each operation. PR2 extends only the
admin route to construct its internal `Authorization` and idempotency headers and to
admit the methods and bounded pagination query parameters the pinned admin API requires.
Keep OIDC and OTLP header, method and URL admission unchanged. Validate every resolved
address, require opt-in for private ranges, verify TLS, cap response framing and size,
and support cancellation. Use a dedicated bounded DNS pool, a 5-second setup and
10-second total ceiling per admin call, and a finite batch deadline. Probe readiness
before mutation. Disable redirects, proxies and transport retries.
[Transport contract](0010-provider-http-transport.md).

Defer transient connectivity failures, upstream `503`, `408 Request Timeout` and
`429 Too Many Requests` to a later sweep with bounded backoff and jitter. Honor a
single valid integer `Retry-After` of 0–86400 seconds by scheduling the next attempt
after the delay, outside the batch deadline if necessary. Keep the original intent and
resolve uncertain effects before replay. Permanent 4xx policy, credential and validation
refusals stop automatic reconciliation until inputs change or an operator repairs the
cause. Failed readiness or admission blocks every dependent destructive step, including
retirement of a working predecessor.

Apply these ADR 0007 mappings before response headers. After streaming starts, signal
failure in the active protocol. Check visibility and local entitlement first. For an
entitled caller, a known failure affecting dispatch or provisioning takes precedence
over an incomplete binding. Use fixed public text and record the failed step and cause
internally. Discard upstream error text. [Application errors](0007-application-api-contract.md#errors)
and [inference errors (ADR 0038)](https://github.com/OpenMettle/openmettle-core/pull/118).

| Evidence | Response and fixed public text | Internal cause |
| --- | --- | --- |
| Inactive caller or hidden target | Apply ADR 0027 first. Return `401 unauthenticated` or concealed `404 not_found`. | Do not probe another account. |
| Visible target and missing model grant, or active family restriction (quiet hours, study hours or per-child switch) | `403 policy` · “Account policy does not permit this model request. Ask your account administrator about access.” | `policy`. Accept a gateway inference 403 as policy only if the pinned profile has a verified typed refusal for that restriction. |
| Entitled actor whose binding is absent, not yet `ready` or awaiting initial sync | `503 provisioning` · “Gateway access for your account is being set up. If this persists, contact your account administrator.” | Check readiness before default model selection to prevent `Model '' was not found` (#254). |
| Admin/service credential refused (401/403), unexplained upstream 401/403, or invalid/bad-gateway response | `502 provider_failure` · “Gateway request failed. Contact the operator with the request ID.” | `service_auth` for confirmed credential refusal, `unknown` for unexplained 401/403, `protocol` for malformed responses or bad gateway. |
| Endpoint unreachable (DNS/connect/TLS refusal) or upstream 503 | `503 unavailable` · “Gateway access is unavailable. Contact the operator with the request ID.” | `transport` |
| Caller-facing gateway deadline expired | `504 timeout` · “The gateway request timed out.” | `timeout` |
| Inference rate limited by the gateway | `429 rate_limited` · “The gateway request was rate limited.” | Forward only a validated bounded retry delay. Do not replay inference. |

Retain #255 (identify the failed step), #258 (stop the transition) and #259 (bounded
readiness) from the [delivery index](https://github.com/OpenMettle/openmettle-core/issues/1).
Record
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

For a server-owned run, bind the reservation to the ADR 0032 run, actor and accounting
scope in the admission transaction. Exact admission replay reuses it. For a caller-owned
completion, the API binds its reservation to the authorized actor and scope without a
run. Grant both inference roles column-scoped `INSERT` on the billable request identity
(request ID, reservation, actor, scope, and run/round when applicable). Each caller must
commit its distinct identity and allocated hold before sending the request ID through
the gateway. A failed or unacknowledged commit bars dispatch. Allocating a portion of a
run hold to a round leaves the total held unchanged.

Give each caller a guarded release for its own proven-unsent pre-send abort. Serialize
release with the transition that hands the request to the transport. Release once only
while the caller can prove no bytes left the process and dispatch cannot subsequently
start. After a possible send or ambiguous handoff, retain the hold for gateway settlement.
Release unallocated run units when no further calls can start. Attribute each charge to
the original request through rotation, revocation and later rounds. Never join by time,
model name or the user's current key.

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
| PR2 · additive schema and store | On fresh and populated PostgreSQL 18, verify previous-writer compatibility, scoped foreign keys and unique principal, budget, generation and intent. Race duplicate intents and stale generations. Assert the gateway-only lifecycle, audit and settlement grants, minimal authority lock grants, and denial for missing or overlapping roles. Issuance can still sync membership and redeem invitations with zero gateway privileges. |
| PR2 · inference roles and dispatch | Under each actual login, commit a per-call identity and reservation before observed HTTP send. Exercise caller-owned completions and leased run rounds. Verify single-envelope lookup for the checked actor, denial for cross-actor/scope, revoked authority, stale lease/session and non-ready binding. Deny direct ciphertext reads and binding or settled-usage writes. Verify exactly one proven-unsent release, refusal after possible send, and no send after unacknowledged commit. |
| PR2 · keys and transport | Check offline key length, ring size, duplicate and cross-ring material, and role-specific seal/unseal access. Test nonce collisions, wrong user/binding/generation AAD, wrong tag, rollover and missing keys. Capture the per-user bearer on both inference paths. Only the reconciliation process can use the admin credential. Verify redaction and unchanged OIDC/OTLP admission. |
| PR2 · gateway admin client | Count requests on synthetic TLS. Exercise pinned methods and pagination, refused addresses, redirects, TLS, readiness stalls and response limits. Contrast bounded 408/429 retries (valid and invalid retry delays) with permanent 4xx refusal. Drop each create reply after remote commit. Recover the same budget, key and usable envelope with zero extra creates or dependent destructive calls. |
| PR3 · reconciliation sweep | Race reconcilers, renewal and disablement/withdrawal. Sweep committed membership changes and invitation redemption without API hints. Exercise the admission states above and grant loss. Verify immediate local refusal, remote convergence, bounded lag, stable budget and no stale reactivation. |
| PR3 · policy and error mapping | Test per-child switches and quiet/study boundaries in the configured family time zone across the spring-forward gap and both occurrences of the fall-back hour. Drive each error row through the caller and assert fixed text, status, internal step/cause and redaction. Verify the pinned route's typed family-policy refusal and an unexplained 403 that yields `502 provider_failure`. |
| PR3 · usage settlement | On PostgreSQL 18 race duplicate reports with cancellation and crash after commit. Deliver final before partial, corrected final, partial/unknown usage, delayed backfill and confirmed no-charge. Assert exact measured/held totals, cross-scope refusal, no duplicate debit, independent multi-round and final-turn counts, and identical results after restart. |

PR2 takes the next available additive migration after coordination with concurrent tracks.
PR3 exercises the worker and settlement against synthetic gateway evidence. Enabling a
selected gateway requires evidence for its pinned admin, family-policy and reporting
contracts, including the typed refusal and daylight-saving boundary cases above. Those gates and V1-17 quota enforcement remain open after PR1.
