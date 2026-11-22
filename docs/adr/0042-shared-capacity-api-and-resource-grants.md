# 0042 — Shared capacity API and serialized resource grants

Proposed for Wave 21d, V1-18 PR1, 22 November 2026. Refs #18.
This record defines the controller decision. Store implementation, API conformance
and runtime qualification have separate delivery gates.

## Problem and scope

A workstation may serve chat and run an image job on the same accelerator.
Both workers can observe enough free VRAM for their own request while the sum
exceeds the device limit. Across nodes, aggregate free bytes can hide a shortage
on one rank. A cancelled job can still use a device after its worker loses its lease.

V1-18 assigns one authority for physical commitments in each managed GPU group.
It covers interactive serving, demand-driven key/value (KV) cache growth and
bounded jobs such as image/video generation, sandbox work and evaluations.
V1-08 owns model serving, V1-19 owns elastic KV and V1-21 owns media execution
and output. The initial qualification target is one workstation. The same
ownership rule applies when the deployment spans multiple nodes.
[Architecture baseline](../../ARCHITECTURE-v1.md) and
[V1-18 acceptance and dependencies](https://github.com/OpenMettle/openmettle-core/issues/18).

## Ownership and fencing

A managed group is a set of devices under one allocation policy. Each physical
device belongs to at most one active group. Changing membership requires draining
or reconciling outstanding commitments before admitting work in the new group.
Kubernetes Dynamic Resource Allocation (DRA) supplies device access. The controller
accounts for physical capacity available through that access.

PostgreSQL holds one active controller lease per `gpu_group_id`. Acquisition after
expiry advances a durable, monotonically increasing `controller_epoch`. Each
observation, commitment, handoff and reconciliation write checks current ownership,
epoch and lease validity against database time in the serialized group decision.
A deposed controller cannot publish an observation or settle a grant.

The adapter fences commands at the point of effect. On takeover the successor
establishes its epoch with each participating backend before reconciling in-flight
commands. An old command delivered after that fence cannot allocate or release.
A backend that cannot establish this ordering leaves the group closed to bursts.
Independent groups can progress under independent leases.

## Observations and fit

The controller publishes a versioned snapshot with a row per device and a summary
for the same group revision. Each row carries the following fields.

| Field | Meaning |
| --- | --- |
| `total_bytes` | Physical backing available to the managed device or group. |
| `committed_bytes` | Outstanding physical promises, including grants awaiting dispatch or release. |
| `actual_used_bytes` | Measured resident use, including use outside controller grants. |
| `reclaimable_bytes` | Resident elastic capacity the adapter identifies as eligible for handback. |
| `safety_headroom_bytes` | Physical margin withheld from allocation. |
| `active_chat_floor_bytes` | Capacity protected for active chat on the required devices. |
| `grantable_bytes` | Conservative additional capacity available for burst grants now. |
| `observation_revision` | Monotonically increasing group revision, preserved across controller epochs. |
| `observed_at` | Measurement time used to enforce the configured freshness TTL. |

Compute fit per device. Charge measured use plus the unbacked portion of each
commitment and the uncovered portion of the chat floor. Subtract these charges
and safety headroom from total bytes, clamping spare capacity at zero.
Deduplicate only overlap attributable to the same backing. Unattributed use
remains charged. Virtual address reservations alone provide no physical backing.
Group totals summarize the devices. A rank-constrained request must fit on each
required device even when the group sum exceeds its requested bytes.

Reading a snapshot never reserves capacity. Within the group decision the
controller includes commitments made since the measurement. Two callers citing
the same revision cannot both consume the last fitting allocation. A missing
rank, inconsistent sample or expired measurement cannot justify a positive grant.
Republishing an old sample cannot extend its freshness.

## Grant, handoff and confirmed backend release

A request identifies the admitted run/job, its authorized step, requested
profile and device footprint, and a stable request identity. Bind that identity
to the scope and immutable request. A retry recovers the same grant decision.
Conflicting reuse cannot change the footprint or repeat dispatch.

A `requested` item has no physical commitment. Under the group fence the
controller can grant immediately or enter `reclaiming_kv` while the serving
adapter shrinks eligible tail backing. Reclaimable bytes become usable only
after matching release evidence from every affected rank and a fresh fit check.
A competing request must pass that same check.

V1-19 protects live contexts within the per-rank base. The pinned serving fork
has a single tail extent. Its adapter owns safe shrink/regrow and evidence of
physical handback. RAM offload requires separate qualification. A grant conveys
no right to read another scope's cache.
[Serving source S27](../../SOURCE-REFERENCES.md#s27) and
[V1-19](https://github.com/OpenMettle/openmettle-core/issues/19).

A `granted` record charges the full footprint before backend dispatch.
For run-linked work, couple the grant and the worker's logical slot handoff in
one database transaction. Validate the current group epoch and the caller's
active run/job lease, bind the durable grant ID, and commit before sending.
The run path uses the active Step claim and `quota_commit_device_handoff`.
An expired or cancelled claim cannot authorize a new allocation. The adapter
accepts only the fenced, idempotent dispatch for that committed grant.

ADR 0040 meters concurrent `device_reservations` slots for the user and project.
A slot permits a handoff within quota. Its count says nothing about device fit,
VRAM bytes or Kubernetes placement. Preserve ADR 0040's transaction and role
boundaries and ADR 0033's execution-time claim checks.
[Quota handoff](0040-transactional-quotas-and-reservation-reconciliation.md) and
[worker leases](0033-worker-leases-deadlines-and-restart-recovery.md).

Completion, cancellation, timeout or lease expiry can trigger `releasing`.
The charge survives that transition. Only confirmed backend release for the
specific allocation and its devices permits `released` and the return of its
bytes to the grantable pool, subject to fresh fit. If dispatch was ambiguous,
positive evidence of non-allocation must also exclude delayed dispatch for that
grant. Record the evidence durably. The worker settles the matching committed
slot through `quota_release_device_slot` against that record, idempotently.

A lost reply, partial rank release or unidentifiable allocation leaves
`unknown_allocation`. Preserve the charge and stop new burst/heavy grants in
the group. A current controller can reconcile after the original worker lease
expires. Recovery authority permits cleanup of the existing grant without
authorizing new work on the expired claim.

## Recovery, priority and bounded waits

On restart or split ownership, suspend burst dispatch. Compare durable grants
with fenced backend inventory and outstanding operations on every required
device. Resume only after ownership is exclusive, all unknowns are resolved and
the group has fresh observations. A stale observation past its TTL has the same
admission effect. Keep the active-chat floor reserved throughout recovery.
Existing chat may continue within its backed base.

Give interactive base service first priority, followed by resuming approved
steps, then fair-share creator/media and other compute jobs. Apply actor/scope
fairness to eligible waiters. Age waiting jobs toward the front of the burst
queue, including ahead of newer resumptions after bounded delay. Aging can
reorder eligible work only within capacity above the chat floor.

Bound queue depth per actor/scope and group. Carry the earlier of the capacity
wait deadline and the work deadline. Recheck authority, lease, deadline and fit
before dispatch. Expire or cancel an ungranted wait without a backend allocation.
An unsatisfiable request cannot hold the head of the queue indefinitely.
[Durable run admission](0032-durable-run-admission-and-fair-work-queue.md).

Use HTTP 429 with the existing quota or rate-limit reason for caller limits.
Use 503 unavailable for group overload, unsafe capacity or an exhausted capacity
wait on a synchronous request. For accepted asynchronous work, record the
capacity wait and its outcome on the caller's run/job. V1-21 retains ownership
of job progress, cancellation and scoped media artifacts.
[Application API](0007-application-api-contract.md) and
[V1-21](https://github.com/OpenMettle/openmettle-core/issues/33).

## Visibility and telemetry

Authenticate and resolve current capability/profile permissions before projecting
availability on `/v1`. Omit inaccessible profiles according to existing disclosure
policy. A user sees only effective availability for authorized work.

| Value | Meaning for this caller |
| --- | --- |
| `ready` | The authorized profile currently appears to fit. |
| `busy` | The profile is eligible but capacity is occupied. |
| `queued_estimate` | The caller's eligible wait has a coarse estimate. |
| `unavailable` | Safe service for the profile cannot currently be established. |

Exclude exact queue positions, other tenants' jobs or scopes, raw host topology
and PCIe IDs. Detailed group/device observations require an explicit operator
or admin capacity capability. Administrative inspection grants no content access.
Physical grants authorize only their bounded operation. Resource assignments
and project membership retain their existing authorization semantics.
[Grant persistence](0006-grant-persistence.md) and
[private project policy](0027-authorization-and-private-projects.md).

Measure capacity wait separately from execution. Count grant outcomes, stale
observations and unresolved handbacks using bounded operation classes and result
codes. Prometheus and OTLP metric labels exclude grant, device, group, user,
scope and job identifiers. Apply the default-deny telemetry allowlist to traces
and logs. A collector outage cannot establish or settle an allocation.
[Telemetry redaction](0024-process-telemetry-and-redaction.md) and
[metrics contract](0028-telemetry-contract-and-metrics.md).

## Alternatives and consequences

- Client-side reservation from a snapshot allows simultaneous spend of the same
  bytes. Group serialization adds a database round trip at each handoff.
- Static chat/creator partitions protect chat but strand idle tail capacity.
  Confirmed elastic handback permits reuse at the cost of reclaim latency.
- Inferring release from DRA claims, quota slots or worker expiry would reuse
  bytes while backend work may still be running. Reconciliation can keep an
  entire group busy until an adapter supplies trustworthy evidence.

## Affected contracts and delivery

1. **PR1** records the V1-18 decision in ADR 0042. Issue #18 stays open.
2. **PR2** delivers an additive migration, fenced controller store, quota handoff
   and release reconciliation, plus the [decisions index](../../DECISIONS.md)
   entry. PostgreSQL 18 tests race two callers for the last bytes and exercise
   takeover with a delayed old-epoch write, stale observations, replay, partial
   release and crash recovery. Assert both ledgers retain their charges until
   confirmation and the active-chat floor survives each failure.
3. **PR3** defines the internal versioned controller/adapter contract and exposes
   authorized capacity through the [OpenAPI contract](../../contracts/openapi/openmettle-v1.json).
   Fixtures cover coarse user and privileged operator responses, denied profiles,
   overload and duplicate or stale adapter messages. Live SGLang handback and
   competing media jobs remain qualification work with V1-19 and V1-21.
