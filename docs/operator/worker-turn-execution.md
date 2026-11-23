# Enabling worker turn execution

This checklist turns on model turn execution in `openmettle-worker`
([ADR 0043](../adr/0043-packaged-worker-inference-configuration.md)). The document format is
described in the README under
[Worker turn execution](../../README.md#worker-turn-execution-off-by-default). Use synthetic
or deployment-private values; never commit site details or key files.

## Before you start

- The schema is migrated, and the API serves run admission with `catalog_file`,
  `admission_limits` and `cursor_keys`.
- Provisional, until the gateway-authorization increment: users who will run turns have
  `ready` gateway bindings for the configured installation, with a sealed key generation and a
  policy for each model they use (ADR 0037). The worker only reads them.
- Every model in the catalog has a route that was qualified for its exact `pin`. A profile with
  `requires_device_slot` stops the worker at startup.

## Files

Mount each file read-only into the worker pod only:

| File | Source | Secret |
| --- | --- | --- |
| Inference document | Deployment configuration | No, but it names the secret files |
| Catalog | The same file as the API's `catalog_file` | No |
| Gateway ring (`gateway_keys`, provisional) | The ring the current credential path opens | Yes |
| Trust bundles | The gateway's issuing CA, when `trust.roots` is `bundle` | No |

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
for PostgreSQL and cluster DNS. For an in-cluster gateway Service, use its cluster DNS name in
`endpoint` and add its Service range to `private_cidrs`. Loopback and cloud metadata addresses
are always refused.

## Verify

1. Start the worker. A refused document exits 78 with
   `inference configuration error: <category>`. Correct the named category and restart.
2. Check `/readyz` on the worker port.
3. Submit a run through `POST /v1/runs` as a user with a ready binding. The run should reach
   `succeeded`, and the gateway should record one request per round with the run's
   `x-request-id`.

## Changes

- **Catalog.** Update the catalog file and the route pins together, then restart the API and the
  worker. A run admitted under another catalog revision fails before its round is reserved.
- **Dispatch credential.** `installation` and `gateway_keys` are provisional (ADR 0043). The
  gateway-authorization increment replaces them and will document their successor.
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
