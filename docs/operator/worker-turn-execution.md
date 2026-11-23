# Enabling worker turn execution

This checklist turns on model turn execution in `openmettle-worker`
([ADR 0043](../adr/0043-packaged-worker-inference-configuration.md)). The document format is
described in the README under
[Worker turn execution](../../README.md#worker-turn-execution-off-by-default). Use synthetic
or deployment-private values; never commit site details or key files.

## Before you start

- The schema is migrated, and the API serves run admission with `catalog_file`,
  `admission_limits` and `cursor_keys`.
- The gateway installation exists. Users who will run turns have `ready` gateway bindings with
  a sealed key generation and a policy for each model they use. The reconciliation process
  provisions these (ADR 0037). The worker only reads them.
- Every model in the catalog has a route that was qualified for its exact `pin`. A profile with
  `requires_device_slot` stops the worker at startup.

## Files

Mount each file read-only into the worker pod only:

| File | Source | Secret |
| --- | --- | --- |
| Inference document | Deployment configuration | No, but it names the secret files |
| Catalog | The same file as the API's `catalog_file` | No |
| Gateway ring (`gateway_keys`) | The unseal keys of the reconciliation process's ring | Yes |
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

Each claimed run borrows short-lived pool connections for lease renewal and its steps, and
maintenance takes one more. The number of slots a `DB_MAX_CONNECTIONS` value sustains has not
been measured.

## Network

Allow egress from the worker to the gateway endpoints only. For an in-cluster gateway Service,
use its cluster DNS name in `endpoint` and add its Service range to `private_cidrs`. Loopback
and cloud metadata addresses are always refused.

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
- **Gateway ring.** Add a new key to the worker's `decrypt_only` list, and to every other
  unsealing process, before the reconciliation process seals with it. Remove an old key only
  after every envelope that uses it has been rewrapped (ADR 0037).
- **Routes.** Re-qualify a route before changing its endpoint, protocol, stream mode or pin.

## Stopping

`SIGTERM` stops claiming, stops in-flight rounds and hands their leases back so another
replica can claim them at once. A round already handed to the gateway still counts against its
run's round budget, and its gateway request keeps its hold until usage settles. After `SIGKILL`
or a lost node, runs wait up to `LEASE_MS` before another worker claims them.
