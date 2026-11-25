# Kubernetes process-contract qualification

This directory qualifies the V1-01 process contract in [`runtime/process-contract.json`](../../runtime/process-contract.json) on a temporary [kind](https://kind.sigs.k8s.io/) cluster. The manifests are test fixtures. They are not an installer, a Helm chart or deployment guidance. Generic packaging belongs to `openmettle-deploy` (V1-32).

## What the run proves

`qualify.py` builds the `api`, `worker` and `gateway` image targets locally and loads them into the cluster. It deploys a synthetic PostgreSQL fixture, one Deployment and ServiceAccount per process, and ClusterIP Services for `openmettle-api` and `openmettle-gateway`, all derived from the contract. Every assertion reads live cluster or process state:

| Check | Observed through |
| --- | --- |
| Image exposes the contract port and runs as `65532:65532` | `docker image inspect` |
| Separate ServiceAccounts, token automount disabled, no token mounted | Live pod spec, ServiceAccount object, `test -e` inside the container |
| Resource requests equal the contract; QoS `Burstable` | Live pod spec and status |
| Each process sees only its own `OPENMETTLE_<ROLE>_` settings, its own credentials and no `PG*` defaults | `/proc/1/environ` of the running binary (values other than the database URL are reported) |
| Liveness `ok` and readiness `ready` | HTTP through `kubectl port-forward`, plus pod `Ready` condition |
| `openmettle-api` and `openmettle-gateway` Services route to their ready pods | Live EndpointSlices for both Services |
| API and gateway stay ready while the worker scales to zero | 4 readiness probes per second during and 10 s after scale-down; same API and gateway pods, no restarts, `readyReplicas` 1 |
| Independent scaling | Worker at 2 ready replicas while the API and gateway stay at 1 |
| Database loss gates readiness only | API and gateway `/readyz` 503, `/healthz` 200, all pods `NotReady`, then recovery with zero restarts |
| Worker maintenance after termination | After SIGTERM scale-down and after a SIGKILL container restart (exit 137), the worker records the expected terminal event and payload for each due queued and executing run. |
| Clean shutdown | Exit code 0 after SIGTERM for every API, worker and gateway container. A temporary finalizer keeps each pod visible until its exit code is read. |

The app namespace enforces the `restricted` Pod Security Standard, so a pod that violates it is rejected and the run fails. Any failed HTTP request, rollout or assertion fails the run. A rendered manifest never counts as evidence. The cluster-free unit tests in `test_qualify.py` cover guards, manifest derivation and recovery assertions.

The fixtures set `enableServiceLinks: false`. Without it, Kubernetes injects variables such as `OPENMETTLE_API_PORT`, `OPENMETTLE_API_SERVICE_HOST`, `OPENMETTLE_GATEWAY_PORT` and `OPENMETTLE_GATEWAY_SERVICE_HOST` into every pod in the namespace. Those names collide with the process configuration prefixes. Deploy packaging should disable service links too.

## Fixture values

Resource requests (`100m` CPU and `64Mi` memory per process) are the contract's example values. Per-process settings differ deliberately to show that the processes are configured independently: the API uses 4 connections and 2000/5000 ms database/shutdown timeouts, the worker uses 2 connections and 1500/4000 ms with a 1,000 ms sweep interval, and the gateway uses 3 connections, 1800/4500 ms timeouts, `UPSTREAM_URL=http://127.0.0.1:30000` and `MODEL=synthetic-model`. None of these is production sizing or tuning. Database passwords are random for each run and are never printed. PostgreSQL uses an `emptyDir` volume and TLS is disabled (`sslmode=disable`). Both are acceptable only for this fixture.

## Safety guards

The harness refuses to run (exit 3) and creates nothing unless all of these hold:

- `OPENMETTLE_K8S_QUALIFICATION=isolated-dev` is set.
- `OPENMETTLE_K8S_DOCKER_CONTEXT` names a Docker context whose endpoint is a local `unix://` socket. `DOCKER_HOST`, or a `DOCKER_CONTEXT` that names a different context, is refused.
- The pinned `kind` and `kubectl` versions are on `PATH`, or in `--tools-dir`.
- The generated cluster name `openmettle-dev-qual-<8 hex>` does not already exist.

The harness strips inherited `KUBECONFIG`, `KIND_*` and builder-selection overrides (`BUILDX_BUILDER`, `BUILDKIT_HOST`, `BUILDX_CONFIG`). Image builds explicitly select the default builder attached to the validated Docker context. It writes the kind kubeconfig to a new temporary directory and passes `--kubeconfig` and `--context` to every `kubectl` call. Before the first change and before each scale operation, it checks the cluster identity: the kubeconfig must hold only the created context, the API server must be loopback, there must be one node named after the cluster, and the node container must carry kind's cluster label. It also refuses to modify a namespace that lacks this run's label. Cleanup deletes only the cluster this run attempted to create and the image tags this run built. Cleanup attempts all owned resources even if one deletion fails. Any cleanup failure makes the run fail, records `cleanup_errors` in the report and retains the temporary kubeconfig for manual recovery. Exit codes: 0 passed, 1 qualification or cleanup failed, 2 invalid contract, 3 refused.

## Running it

CI runs [`.github/workflows/kubernetes.yml`](../../.github/workflows/kubernetes.yml) on GitHub-hosted `ubuntu-24.04`, where the default Docker context is the runner's isolated local daemon. The job summary records the observed values.

```sh
python3 -m unittest discover -s tests/kubernetes -v   # guards and fixtures, no cluster
```

A local run needs a disposable Linux Docker daemon reached through a `unix://` context, linux/amd64 for `install-tools.sh`, and capacity for the Rust build cache, container images, cluster and PostgreSQL fixture. Peak disk and memory requirements have not been measured. Do not point it at a workstation or serving stack daemon.

```sh
bash tests/kubernetes/install-tools.sh "$(mktemp -d)/tools"
OPENMETTLE_K8S_QUALIFICATION=isolated-dev OPENMETTLE_K8S_DOCKER_CONTEXT=default \
  python3 tests/kubernetes/qualify.py --tools-dir <that directory>/tools --report /tmp/qualification.json
```

## Pinned tooling

| Tool | Pin | Origin | Licence |
| --- | --- | --- | --- |
| kind | v0.33.0, `kind-linux-amd64` SHA-256 `aee61515…8e0d` (tag commit `407a9675`) | https://github.com/kubernetes-sigs/kind | Apache-2.0 |
| kubectl | v1.37.0, linux/amd64 SHA-256 `6129359f…1a2f` | https://dl.k8s.io (Kubernetes release) | Apache-2.0 |
| kind node image | `kindest/node:v1.37.0@sha256:a1ed56cf…0ae5` (Kubernetes 1.37.0) | kind v0.33.0 release notes | Apache-2.0 (Kubernetes); bundled OS packages carry their own licences |
| PostgreSQL fixture | `postgres:18.1-bookworm@sha256:cc9f4143…221a`, the same image as CI | https://github.com/docker-library/postgres | See [ADR 0002](../../docs/adr/0002-cpu-runtime.md) |

Full digests are in `install-tools.sh` and `qualify.py`. They were resolved on 16 November 2026 from the kind release API, the published `.sha256` files and the Docker Hub registry. The licences were read from each project's `LICENSE` at the pinned tag. These tools are test-only and are not distributed. They are recorded as pending in [`provenance/register.json`](../../provenance/register.json). Their presence there is not a distribution review.

## Limitations

- One single-node kind cluster on amd64. Multi-node scheduling, network policy, resource limits, autoscaling, real storage and TLS are not exercised.
- Requests are scheduled, but they are not shown to be sufficient under load.
- No RBAC is granted. The processes do not call the Kubernetes API, so no Role is needed.
- The fixture applies the release schema to exercise maintenance. Live run execution and lease handover in kind require the V1-07 executor.
