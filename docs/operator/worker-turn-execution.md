# Enabling worker turn execution

This checklist turns on model turn execution in `openmettle-worker`
([ADR 0043](../adr/0043-packaged-worker-inference-configuration.md)). The document format is
described in the README under
[Worker turn execution](../../README.md#worker-turn-execution-off-by-default). Use synthetic
or deployment-private values; never commit site details or key files.

## Before you start

- The schema is migrated, and the API serves run admission with `catalog_file`,
  `admission_limits` and `cursor_keys`.
- `openmettle-gateway` ([gateway proxy](gateway-proxy.md)) serves each catalog model and can
  reach its SGLang upstream. Users need no gateway binding, key or policy: each round is
  authorized at handoff and carries its own bearer
  ([ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md)).
- Every model in the catalog has a route that was qualified for its exact `pin`. A profile with
  `requires_device_slot` stops the worker at startup.

## Files

Mount each file read-only into the worker pod only:

| File | Source | Secret |
| --- | --- | --- |
| Inference document | Deployment configuration | No |
| Catalog | The same file as the API's `catalog_file` | No |
| Trust bundles | The issuing CA of an `https://` route, when `trust.roots` is `bundle` | No |

Do not mount the API's `auth.json`, login keys, cursor keys or issuance credential into the
worker.

## Environment

Set these with the `OPENMETTLE_WORKER_` prefix:

- `RUN_SLOTS`, `LEASE_MS`, `EXECUTION_TIMEOUT_MS`, `EXECUTING_PER_ACTOR` and
  `EXECUTING_PER_SCOPE` (ADR 0033 ranges in the README).
- `INFERENCE_CONFIG`: the absolute path of the mounted document.
- `ARTIFACTS_DIR`: the API's payload directory, when turns may include attachments.
- `SHUTDOWN_TIMEOUT_MS`: half of it drains in-flight runs. Keep the pod's termination grace
  period above it.

`DB_MAX_CONNECTIONS` has no minimum beyond the usual one. No task on the turn path waits for
a second pooled connection while it holds one; prompt assembly reads attachments on the
connection it already holds. Each claimed run uses at most two connections at a time, one for
its step and one for its lease renewal, and the sweeps use one more, so run and maintenance
work needs at most `2 × RUN_SLOTS + 1`. Each `/readyz` probe in flight takes one more from the
same pool. With one probe at a time, `2 × RUN_SLOTS + 2` connections let nothing wait. With a
smaller pool, tasks queue for up to `DB_TIMEOUT_MS`. A `/readyz` that cannot get a connection
in that time answers 503 `not ready`: work continues, but repeated failures mark the pod not
ready. How much throughput a given size sustains has not been measured.

## Network

Limit the worker's inference egress to the gateway endpoints. Keep the rules it already needs
for PostgreSQL and cluster DNS. For an in-cluster gateway Service, use its fully qualified
cluster DNS name in `endpoint` (a name without a dot is refused) and add its Service range to
`private_cidrs`. Loopback and cloud metadata addresses are always refused.

### Plain HTTP inside the cluster

A route may name `openmettle-gateway` with an `http://` endpoint and no `trust` member. The
worker then connects without TLS, and the following cross the cluster network unencrypted:

- the round's bearer, in `Authorization`;
- the request ID, and the prompt the worker sends, including conversation history and
  attachments;
- the model's response.

The bearer authorizes one dispatch of one handed-off request: the gateway spends it before
reading the body, and it is worthless after that dispatch or once the run's lease or deadline
has passed. Someone who can observe the traffic can still read every prompt and response.

Mitigate with a NetworkPolicy that admits only the worker pods to the gateway's port, and the
gateway's egress only to its SGLang upstream and PostgreSQL. For anything stricter, use TLS:
terminate it in front of the gateway, for example in a sidecar, and give the route an
`https://` endpoint with the terminator's trust anchors. The gateway itself has no TLS
listener. Mutual TLS is not supported.

## Verify

1. Start the worker. A refused document exits 78 with
   `inference configuration error: <category>`. Correct the named category and restart.
2. Check `/readyz` on the worker port.
3. Submit a run through `POST /v1/runs`. The run should reach `succeeded`, each round's
   gateway request should show `dispatched_at` and one final usage report, and its token hold
   should be `settled`.

## Changes

- **Catalog.** Update the catalog file and the route pins together, then restart the API and the
  worker. A run admitted under another catalog revision fails before its round is reserved.
- **Upgrading from a document with `gateway_keys`.** The member was removed on
  24 November 2026 (ADR 0044 increment 2c). A worker of this release refuses a document that
  still has it (`inference configuration error: configuration has an unknown field`), and an
  earlier worker refuses one without it, so change the document and the image together. The
  ring's key files are no longer needed by the worker; unmount them.
- **Routes.** Re-qualify a route before changing its endpoint, protocol, stream mode or pin.

## Stopping

`SIGTERM` stops claiming and stops in-flight rounds. The worker keeps answering probes while,
within half the drain budget, each run waits at most `LEASE_MS / 6` for its step to stop and
then hands its lease back, so another replica can claim it at once. A run whose handoff does not
finish in that time is dropped, and its lease lapses: another worker claims it after up to
`LEASE_MS`, as after a crash (ADR 0033). The default 5 s `SHUTDOWN_TIMEOUT_MS` leaves a short
handoff window. Raise it, and the pod's termination grace period, when immediate re-claim
matters.

A round already handed to the gateway still counts against its run's round budget, and its
gateway request keeps its hold until usage settles. After `SIGKILL` or a lost node, runs wait
up to `LEASE_MS` before another worker claims them.
