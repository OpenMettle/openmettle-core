#!/usr/bin/env python3
"""Qualify the core API/worker process contract on an ephemeral kind cluster (V1-01).

Test fixture only: this is not an installer, Helm chart or deployment manifest. The harness
creates a uniquely named kind cluster classified `dev`, uses a temporary kubeconfig, builds
local images without publishing them, and deletes only the cluster and image tags it created.
Assertions read live pod, ServiceAccount, process and HTTP state; manifests are derived from
runtime/process-contract.json so the contract and the exercised fixture cannot drift silently.

Requires Python 3.10+, docker, and the pinned kind/kubectl from install-tools.sh.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "runtime" / "process-contract.json"

OPT_IN_VAR = "OPENMETTLE_K8S_QUALIFICATION"
OPT_IN_VALUE = "isolated-dev"
DOCKER_CONTEXT_VAR = "OPENMETTLE_K8S_DOCKER_CONTEXT"
KIND_VERSION = "v0.33.0"
KUBECTL_VERSION = "v1.37.0"
NODE_IMAGE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
POSTGRES_IMAGE = ("docker.io/library/postgres:18.1-bookworm"
                  "@sha256:cc9f4143a8d2fa8cf3749d0cb4d26ecf2d53a77a2ac807e9ebd67ae22426221a")
CLUSTER_NAME = re.compile(r"openmettle-dev-qual-[0-9a-f]{8}")
APP_NAMESPACE = "openmettle-qualification"
DB_NAMESPACE = "openmettle-qualification-db"
FINALIZER = "openmettle.dev/observe-termination"
ROLES = ("api", "worker")
# Exercised fixture values. They differ per process to prove independent configuration;
# they are not production sizing or tuning.
FIXTURE_SETTINGS = {
    "api": {"DB_MAX_CONNECTIONS": "4", "DB_TIMEOUT_MS": "2000", "SHUTDOWN_TIMEOUT_MS": "5000"},
    "worker": {"DB_MAX_CONNECTIONS": "2", "DB_TIMEOUT_MS": "1500", "SHUTDOWN_TIMEOUT_MS": "4000"},
}
IMAGE_USER = "65532:65532"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
# Environment that could redirect tools to an inherited cluster or daemon.
STRIPPED_ENV = ("KUBECONFIG", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG_CONTEXT",
                "KIND_CLUSTER_NAME", "KIND_EXPERIMENTAL_PROVIDER", "BUILDX_BUILDER",
                "BUILDKIT_HOST", "BUILDX_CONFIG")
DNS_LABEL = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")


class Refusal(Exception):
    """A safety guard refused to run; nothing was created."""


class ContractError(Exception):
    """runtime/process-contract.json cannot be used as a test source."""


class QualificationFailure(Exception):
    """Observed cluster behavior did not match the contract."""


# --- Contract and fixture manifests -------------------------------------------------------

def load_contract(path: Path = CONTRACT) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ContractError(f"{path.name}: unreadable: {exc}") from exc
    return validate_contract(data)


def validate_contract(data: object) -> dict:
    if not isinstance(data, dict):
        raise ContractError("contract must be an object")
    for role in ROLES:
        spec = data.get(role)
        if not isinstance(spec, dict):
            raise ContractError(f"{role}: missing process entry")
        if spec.get("imageTarget") != role:
            raise ContractError(f"{role}: imageTarget must be '{role}'")
        if spec.get("configurationPrefix") != f"OPENMETTLE_{role.upper()}_":
            raise ContractError(f"{role}: unexpected configurationPrefix")
        port = spec.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
            raise ContractError(f"{role}: port must be an unprivileged integer")
        name = spec.get("serviceAccountName")
        if not isinstance(name, str) or not DNS_LABEL.fullmatch(name):
            raise ContractError(f"{role}: serviceAccountName must be a DNS label")
        if spec.get("automountServiceAccountToken") is not False:
            raise ContractError(f"{role}: automountServiceAccountToken must be false")
        requests = spec.get("requests")
        if (not isinstance(requests, dict) or set(requests) != {"cpu", "memory"}
                or not all(isinstance(v, str) and v for v in requests.values())):
            raise ContractError(f"{role}: requests must contain cpu and memory strings")
        for key in ("livenessPath", "readinessPath"):
            if not isinstance(spec.get(key), str) or not spec[key].startswith("/"):
                raise ContractError(f"{role}: {key} must be an absolute path")
    for key in ("port", "serviceAccountName", "configurationPrefix"):
        if data["api"][key] == data["worker"][key]:
            raise ContractError(f"api and worker must not share {key}")
    return data


def database_url(role: str, password: str) -> str:
    host = f"postgres.{DB_NAMESPACE}.svc.cluster.local"
    return f"postgres://openmettle_{role}:{password}@{host}:5432/fixture?sslmode=disable"


def render_manifests(contract: dict, images: dict, passwords: dict, run_id: str) -> dict:
    """Return a kubectl List. passwords holds synthetic per-run values for admin/api/worker."""
    labels = {"openmettle.dev/environment": "dev", "openmettle.dev/qualification-run": run_id}
    items = [
        {"apiVersion": "v1", "kind": "Namespace",
         "metadata": {"name": APP_NAMESPACE, "labels": {
             **labels,
             "pod-security.kubernetes.io/enforce": "restricted",
             "pod-security.kubernetes.io/enforce-version": "latest"}}},
        {"apiVersion": "v1", "kind": "Namespace",
         "metadata": {"name": DB_NAMESPACE, "labels": labels}},
    ]
    roles_sql = "".join(
        f"CREATE ROLE openmettle_{role} LOGIN PASSWORD '{passwords[role]}';\n" for role in ROLES)
    items += [
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": "postgres-fixture", "namespace": DB_NAMESPACE},
         "stringData": {"admin-password": passwords["admin"], "roles.sql": roles_sql}},
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": "postgres", "namespace": DB_NAMESPACE},
         "spec": {
             "replicas": 1, "strategy": {"type": "Recreate"},
             "selector": {"matchLabels": {"app.kubernetes.io/name": "postgres"}},
             "template": {
                 "metadata": {"labels": {"app.kubernetes.io/name": "postgres"}},
                 "spec": {
                     "automountServiceAccountToken": False,
                     "enableServiceLinks": False,
                     "containers": [{
                         "name": "postgres", "image": POSTGRES_IMAGE,
                         "imagePullPolicy": "IfNotPresent",
                         "env": [
                             {"name": "POSTGRES_USER", "value": "fixture_admin"},
                             {"name": "POSTGRES_DB", "value": "fixture"},
                             {"name": "POSTGRES_PASSWORD", "valueFrom": {"secretKeyRef": {
                                 "name": "postgres-fixture", "key": "admin-password"}}},
                         ],
                         "ports": [{"name": "postgres", "containerPort": 5432}],
                         "readinessProbe": {
                             "exec": {"command": ["pg_isready", "-h", "127.0.0.1",
                                                  "-U", "fixture_admin", "-d", "fixture"]},
                             "periodSeconds": 2, "failureThreshold": 2},
                         "volumeMounts": [
                             {"name": "data", "mountPath": "/var/lib/postgresql"},
                             {"name": "init", "mountPath": "/docker-entrypoint-initdb.d",
                              "readOnly": True},
                         ],
                     }],
                     "volumes": [
                         {"name": "data", "emptyDir": {}},
                         {"name": "init", "secret": {"secretName": "postgres-fixture",
                                                     "items": [{"key": "roles.sql",
                                                                "path": "roles.sql"}]}},
                     ],
                 }}}},
        {"apiVersion": "v1", "kind": "Service",
         "metadata": {"name": "postgres", "namespace": DB_NAMESPACE},
         "spec": {"selector": {"app.kubernetes.io/name": "postgres"},
                  "ports": [{"name": "postgres", "port": 5432, "targetPort": "postgres"}]}},
    ]
    for role in ROLES:
        spec = contract[role]
        prefix = spec["configurationPrefix"]
        name = f"openmettle-{role}"
        selector = {"app.kubernetes.io/name": name}
        env = [{"name": f"{prefix}BIND", "value": f"0.0.0.0:{spec['port']}"},
               {"name": f"{prefix}DATABASE_URL", "valueFrom": {"secretKeyRef": {
                   "name": f"{name}-database", "key": "url"}}}]
        env += [{"name": prefix + k, "value": v} for k, v in FIXTURE_SETTINGS[role].items()]
        items += [
            {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
             "metadata": {"name": f"{name}-database", "namespace": APP_NAMESPACE},
             "stringData": {"url": database_url(role, passwords[role])}},
            {"apiVersion": "v1", "kind": "ServiceAccount",
             "metadata": {"name": spec["serviceAccountName"], "namespace": APP_NAMESPACE},
             "automountServiceAccountToken": spec["automountServiceAccountToken"]},
            {"apiVersion": "apps/v1", "kind": "Deployment",
             "metadata": {"name": name, "namespace": APP_NAMESPACE, "labels": selector},
             "spec": {
                 "replicas": 1,
                 "selector": {"matchLabels": selector},
                 "template": {
                     "metadata": {"labels": {**selector, "app.kubernetes.io/component": role}},
                     "spec": {
                         "serviceAccountName": spec["serviceAccountName"],
                         "automountServiceAccountToken": spec["automountServiceAccountToken"],
                         # Service links would inject OPENMETTLE_API_* variables into every pod.
                         "enableServiceLinks": False,
                         "terminationGracePeriodSeconds": 15,
                         "securityContext": {"runAsNonRoot": True,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{
                             "name": role, "image": images[role], "imagePullPolicy": "Never",
                             "ports": [{"name": "http", "containerPort": spec["port"]}],
                             "env": env,
                             "resources": {"requests": dict(spec["requests"])},
                             "readinessProbe": {
                                 "httpGet": {"path": spec["readinessPath"], "port": "http"},
                                 "periodSeconds": 2, "failureThreshold": 2, "timeoutSeconds": 3},
                             "livenessProbe": {
                                 "httpGet": {"path": spec["livenessPath"], "port": "http"},
                                 "periodSeconds": 5, "failureThreshold": 3, "timeoutSeconds": 3},
                             "securityContext": {
                                 "allowPrivilegeEscalation": False,
                                 "readOnlyRootFilesystem": True,
                                 "capabilities": {"drop": ["ALL"]}},
                         }],
                     }}}},
        ]
    api = contract["api"]
    items.append(
        {"apiVersion": "v1", "kind": "Service",
         "metadata": {"name": "openmettle-api", "namespace": APP_NAMESPACE},
         "spec": {"selector": {"app.kubernetes.io/name": "openmettle-api"},
                  "ports": [{"name": "http", "port": api["port"], "targetPort": "http"}]}})
    return {"apiVersion": "v1", "kind": "List", "items": items}


# --- Safety guards -------------------------------------------------------------------------

def child_environment(environ: dict, kubeconfig: Path, docker_context: str,
                      tools_dir: Path | None) -> dict:
    env = {k: v for k, v in environ.items() if k not in STRIPPED_ENV}
    env["KUBECONFIG"] = str(kubeconfig)
    env["DOCKER_CONTEXT"] = docker_context
    env["KIND_EXPERIMENTAL_PROVIDER"] = "docker"
    if tools_dir is not None:
        env["PATH"] = f"{tools_dir}{os.pathsep}{env.get('PATH', '')}"
    return env


def check_opt_in(environ: dict) -> str:
    """Return the explicitly named Docker context or refuse."""
    if environ.get(OPT_IN_VAR) != OPT_IN_VALUE:
        raise Refusal(f"set {OPT_IN_VAR}={OPT_IN_VALUE} to create an isolated dev kind cluster")
    context = environ.get(DOCKER_CONTEXT_VAR, "")
    if not context:
        raise Refusal(f"set {DOCKER_CONTEXT_VAR} to the isolated local Docker context to use")
    if environ.get("DOCKER_HOST"):
        raise Refusal("DOCKER_HOST is set; select an isolated local daemon through a Docker context")
    if environ.get("DOCKER_CONTEXT") not in (None, context):
        raise Refusal("DOCKER_CONTEXT differs from the opted-in context")
    return context


def check_tools(run) -> None:
    out = run(["kind", "version"]).stdout
    if KIND_VERSION not in out.split():
        raise Refusal(f"kind {KIND_VERSION} required (use tests/kubernetes/install-tools.sh)")
    client = json.loads(run(["kubectl", "version", "--client", "--output=json"]).stdout)
    if client.get("clientVersion", {}).get("gitVersion") != KUBECTL_VERSION:
        raise Refusal(f"kubectl {KUBECTL_VERSION} required (use tests/kubernetes/install-tools.sh)")


def check_docker_context(run, context: str) -> None:
    data = json.loads(run(["docker", "context", "inspect", context]).stdout)
    host = data[0].get("Endpoints", {}).get("docker", {}).get("Host", "") if data else ""
    if not host.startswith("unix://"):
        raise Refusal(f"Docker context '{context}' is not a local unix socket daemon")


def check_cluster_absent(run, name: str) -> None:
    if not CLUSTER_NAME.fullmatch(name):
        raise Refusal("cluster name must be openmettle-dev-qual-<8 hex>")
    existing = run(["kind", "get", "clusters"]).stdout.split()
    if name in existing:
        raise Refusal(f"kind cluster {name} already exists; refusing to reuse it")


def check_cluster_identity(config: dict, nodes: list, node_label: str, name: str) -> None:
    """Fail unless the temporary kubeconfig, API server, node and container all identify `name`.

    config is the redacted `kubectl config view` of the temporary kubeconfig, read without a
    --context override; nodes are the API server's node names; node_label is the kind cluster
    label on the node container.
    """
    context = f"kind-{name}"
    if config.get("current-context") != context:
        raise Refusal("temporary kubeconfig does not select the created kind context")
    if [c.get("name") for c in config.get("contexts") or []] != [context]:
        raise Refusal("temporary kubeconfig contains contexts this run did not create")
    clusters = config.get("clusters") or []
    if [c.get("name") for c in clusters] != [context]:
        raise Refusal("temporary kubeconfig contains clusters this run did not create")
    server = clusters[0].get("cluster", {}).get("server", "")
    if not re.fullmatch(r"https://127\.0\.0\.1:\d+", server):
        raise Refusal("kind API server is not a loopback endpoint")
    if nodes != [f"{name}-control-plane"]:
        raise Refusal("cluster nodes do not match the created kind cluster")
    if node_label != name:
        raise Refusal("node container is not labelled with the created kind cluster")


# --- Harness ---------------------------------------------------------------------------------

def _log(message: str) -> None:
    print(f"[qualify] {message}", file=sys.stderr, flush=True)


class Runner:
    def __init__(self, env: dict):
        self.env = env

    def __call__(self, args, *, input=None, check=True, timeout=600):
        try:
            result = subprocess.run(args, input=input, capture_output=True, text=True,
                                    env=self.env, timeout=timeout)
        except FileNotFoundError as exc:
            raise Refusal(f"{args[0]} not found on PATH") from exc
        if check and result.returncode != 0:
            raise QualificationFailure(
                f"{' '.join(args[:4])} ... exited {result.returncode}: {result.stderr.strip()[-2000:]}")
        return result


def http_get(port: int, path: str):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except OSError as exc:
        return None, str(exc)


class PortForward:
    def __init__(self, kubectl_args, env, target: str, port: int):
        self.proc = subprocess.Popen(
            [*kubectl_args, "--namespace", APP_NAMESPACE, "port-forward", "--address", "127.0.0.1", target, f":{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        lines: queue.Queue = queue.Queue()

        def read():
            for line in self.proc.stdout:
                lines.put(line)
        threading.Thread(target=read, daemon=True).start()
        deadline = time.monotonic() + 30
        while True:
            try:
                line = lines.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                self.close()
                raise QualificationFailure(f"port-forward to {target} did not start")
            match = re.match(r"Forwarding from 127\.0\.0\.1:(\d+) ->", line)
            if match:
                self.port = int(match.group(1))
                return

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class Qualification:
    def __init__(self, contract: dict, environ: dict, tools_dir: Path | None, workdir: Path):
        self.contract = contract
        self.context = check_opt_in(environ)
        self.run_id = secrets.token_hex(4)
        self.name = f"openmettle-dev-qual-{self.run_id}"
        self.kubeconfig = workdir / "kubeconfig"
        self.env = child_environment(environ, self.kubeconfig, self.context, tools_dir)
        self.run = Runner(self.env)
        self.kubectl = ["kubectl", "--kubeconfig", str(self.kubeconfig),
                        "--context", f"kind-{self.name}"]
        self.images = {role: f"openmettle-{role}:k8s-qual-{self.run_id}" for role in ROLES}
        self.cluster_attempted = False
        self.built_images: list[str] = []
        self.report: dict = {"cluster": self.name, "classification": "dev",
                             "kind": KIND_VERSION, "kubectl": KUBECTL_VERSION,
                             "node_image": NODE_IMAGE, "checks": []}

    # helpers
    def kube(self, *args, input=None, check=True, timeout=300):
        return self.run([*self.kubectl, *args], input=input, check=check, timeout=timeout)

    def kube_json(self, args):
        return json.loads(self.kube(*args).stdout)

    def passed(self, check: str, **observed):
        self.report["checks"].append({"check": check, **observed})
        _log(f"PASS {check}")

    def expect(self, condition: bool, message: str):
        if not condition:
            raise QualificationFailure(message)

    def wait_for(self, description: str, predicate, timeout=120, interval=1.0):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = predicate()
            if last:
                return last
            time.sleep(interval)
        raise QualificationFailure(f"timed out waiting for {description}")

    def pods(self, role: str, include_terminating=False) -> list[dict]:
        items = self.kube_json(["--namespace", APP_NAMESPACE, "get", "pods", "--selector",
                                f"app.kubernetes.io/name=openmettle-{role}", "--output=json"])["items"]
        if include_terminating:
            return items
        return [p for p in items if not p["metadata"].get("deletionTimestamp")]

    # phases
    def preflight(self):
        check_tools(self.run)
        check_docker_context(self.run, self.context)
        check_cluster_absent(self.run, self.name)
        if self.kubeconfig.exists():
            raise Refusal("temporary kubeconfig already exists")

    def verify_identity(self):
        config = json.loads(self.run(["kubectl", "--kubeconfig", str(self.kubeconfig),
                                      "config", "view", "--output=json"]).stdout)
        nodes = [n["metadata"]["name"]
                 for n in self.kube_json(["get", "nodes", "--output=json"])["items"]]
        label = self.run(["docker", "inspect", "--format",
                          '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}',
                          f"{self.name}-control-plane"]).stdout.strip()
        check_cluster_identity(config, nodes, label, self.name)
        for ns in (APP_NAMESPACE, DB_NAMESPACE):
            found = self.kube("get", "namespace", ns, "--output=json", check=False)
            if found.returncode == 0:
                labels = json.loads(found.stdout)["metadata"].get("labels", {})
                if labels.get("openmettle.dev/qualification-run") != self.run_id:
                    raise Refusal(f"namespace {ns} was not created by this run")

    def build_images(self):
        for role in ROLES:
            _log(f"building {self.images[role]} (local only; never pushed)")
            self.built_images.append(self.images[role])
            self.run(["docker", "build", "--builder", "default", "--target", self.contract[role]["imageTarget"],
                      "--tag", self.images[role], str(ROOT)], timeout=1800)
            config = json.loads(self.run(["docker", "image", "inspect", "--format",
                                          "{{json .Config}}", self.images[role]]).stdout)
            port = f"{self.contract[role]['port']}/tcp"
            self.expect(port in (config.get("ExposedPorts") or {}),
                        f"{role} image does not expose contract port {port}")
            self.expect(config.get("User") == IMAGE_USER, f"{role} image user is not {IMAGE_USER}")
            self.expect(config.get("Entrypoint") == [f"/usr/local/bin/openmettle-{role}"],
                        f"{role} image entrypoint does not match its process")
            self.passed(f"{role} image config matches contract", exposed=port, user=IMAGE_USER)

    def create_cluster(self):
        _log(f"creating kind cluster {self.name} (dev, temporary kubeconfig)")
        self.cluster_attempted = True
        self.run(["kind", "create", "cluster", "--name", self.name, "--image", NODE_IMAGE,
                  "--kubeconfig", str(self.kubeconfig), "--wait", "180s"], timeout=900)
        self.verify_identity()
        self.passed("isolated cluster identity", context=f"kind-{self.name}")
        for role in ROLES:
            self.run(["kind", "load", "docker-image", self.images[role], "--name", self.name],
                     timeout=600)

    def deploy(self):
        passwords = {k: secrets.token_hex(16) for k in ("admin", *ROLES)}
        manifests = render_manifests(self.contract, self.images, passwords, self.run_id)
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(manifests))
        self.kube("--namespace", DB_NAMESPACE, "rollout", "status", "deployment/postgres",
                  "--timeout=300s", timeout=330)
        for role in ROLES:
            self.kube("--namespace", APP_NAMESPACE, "rollout", "status",
                      f"deployment/openmettle-{role}", "--timeout=180s", timeout=210)

    def exec(self, pod: str, *command: str):
        return self.kube("--namespace", APP_NAMESPACE, "exec", pod, "--", *command).stdout

    def process_environment(self, pod: str) -> dict:
        raw = self.exec(pod, "cat", "/proc/1/environ")
        return dict(item.split("=", 1) for item in raw.split("\0") if "=" in item)

    def observe_process(self, role: str) -> dict:
        """Inspect one ready pod's live spec, ServiceAccount, process and HTTP endpoints."""
        spec = self.contract[role]
        other = "worker" if role == "api" else "api"
        pods = self.pods(role)
        self.expect(len(pods) >= 1, f"no {role} pod")
        pod = pods[0]
        pod_name = pod["metadata"]["name"]
        pod_spec = pod["spec"]
        container = pod_spec["containers"][0]
        self.expect(pod_spec.get("serviceAccountName") == spec["serviceAccountName"],
                    f"{role} pod runs as the wrong ServiceAccount")
        self.expect(pod_spec.get("automountServiceAccountToken") is False,
                    f"{role} pod does not disable token automount")
        self.expect(not any("projected" in v for v in pod_spec.get("volumes", [])),
                    f"{role} pod received a projected token volume")
        self.expect(not any(m["mountPath"].startswith("/var/run/secrets/kubernetes.io")
                            for m in container.get("volumeMounts", [])),
                    f"{role} container mounts a ServiceAccount token")
        self.expect(container.get("resources", {}).get("requests") == spec["requests"],
                    f"{role} live resource requests differ from contract")
        self.expect(container["readinessProbe"]["httpGet"]["path"] == spec["readinessPath"]
                    and container["livenessProbe"]["httpGet"]["path"] == spec["livenessPath"],
                    f"{role} live probes differ from contract")
        account = self.kube_json(["--namespace", APP_NAMESPACE, "get", "serviceaccount",
                                  spec["serviceAccountName"], "--output=json"])
        self.expect(account.get("automountServiceAccountToken") is False,
                    f"{role} ServiceAccount allows token automount")
        status = pod["status"]
        ready = {c["type"]: c["status"] for c in status.get("conditions", [])}.get("Ready")
        self.expect(ready == "True", f"{role} pod is not Ready")
        self.expect(status.get("qosClass") == "Burstable", f"{role} pod QoS is not Burstable")
        self.expect(all(c.get("restartCount") == 0 for c in status["containerStatuses"]),
                    f"{role} container restarted")
        # Live process state, not the rendered manifest.
        env = self.process_environment(pod_name)
        configured = sorted(k for k in env if k.startswith("OPENMETTLE_"))
        self.expect(all(k.startswith(spec["configurationPrefix"]) for k in configured),
                    f"{role} process sees foreign OPENMETTLE_ variables: {configured}")
        self.expect(not any(k.startswith(self.contract[other]["configurationPrefix"]) for k in env),
                    f"{role} process sees {other} configuration")
        self.expect(not any(k.startswith("PG") for k in env), f"{role} process sees PG* defaults")
        self.expect(f"{spec['configurationPrefix']}DATABASE_URL" in env,
                    f"{role} process has no database URL")
        settings = {k[len(spec["configurationPrefix"]):]: env[k] for k in configured
                    if not k.endswith("DATABASE_URL")}
        self.expect(settings == {"BIND": f"0.0.0.0:{spec['port']}", **FIXTURE_SETTINGS[role]},
                    f"{role} process settings differ: {settings}")
        uid = re.search(r"^Uid:\s+\d+\s+(\d+)", self.exec(pod_name, "cat", "/proc/1/status"),
                        re.MULTILINE)
        self.expect(uid is not None and uid.group(1) == IMAGE_USER.split(":")[0],
                    f"{role} process is not running as {IMAGE_USER}")
        token = self.kube("--namespace", APP_NAMESPACE, "exec", pod_name, "--",
                          "test", "-e", TOKEN_PATH, check=False)
        self.expect(token.returncode == 1, f"{role} pod has a ServiceAccount token path")
        forward = PortForward(self.kubectl, self.env, f"pod/{pod_name}", spec["port"])
        try:
            health = http_get(forward.port, spec["livenessPath"])
            readiness = http_get(forward.port, spec["readinessPath"])
        finally:
            forward.close()
        self.expect(health == (200, "ok\n"), f"{role} liveness returned {health}")
        self.expect(readiness == (200, "ready\n"), f"{role} readiness returned {readiness}")
        observed = {"pod": pod_name, "serviceAccount": pod_spec["serviceAccountName"],
                    "automountServiceAccountToken": False, "requests": spec["requests"],
                    "qosClass": status["qosClass"], "settings": settings,
                    "uid": uid.group(1), "healthz": health[0], "readyz": readiness[0]}
        self.passed(f"{role} live process contract", **observed)
        return observed

    def deployment(self, role: str) -> dict:
        return self.kube_json(["--namespace", APP_NAMESPACE, "get", "deployment",
                               f"openmettle-{role}", "--output=json"])

    def scale(self, role: str, replicas: int, namespace=APP_NAMESPACE, name=None):
        self.verify_identity()
        self.kube("--namespace", namespace, "scale", f"deployment/{name or 'openmettle-' + role}",
                  f"--replicas={replicas}")

    def scale_down_observing_exit(self, role: str):
        """Scale to zero and require each container to exit 0 (graceful SIGTERM) before removal."""
        names = [p["metadata"]["name"] for p in self.pods(role)]
        patch = json.dumps([{"op": "add", "path": "/metadata/finalizers", "value": [FINALIZER]}])
        for name in names:
            self.kube("--namespace", APP_NAMESPACE, "patch", "pod", name, "--type=json",
                      f"--patch={patch}")
        self.scale(role, 0)
        exits = {}
        for name in names:
            def terminated(name=name):
                pod = self.kube_json(["--namespace", APP_NAMESPACE, "get", "pod", name,
                                      "--output=json"])
                state = pod["status"].get("containerStatuses", [{}])[0].get("state", {})
                return state.get("terminated")
            state = self.wait_for(f"{name} to terminate", terminated, timeout=60)
            exits[name] = state.get("exitCode")
            self.kube("--namespace", APP_NAMESPACE, "patch", "pod", name, "--type=json",
                      '--patch=[{"op":"remove","path":"/metadata/finalizers"}]')
        self.expect(all(code == 0 for code in exits.values()),
                    f"{role} did not shut down cleanly: {exits}")
        self.wait_for(f"{role} pods to be removed",
                      lambda: not self.pods(role, include_terminating=True), timeout=60)
        return exits

    def scenario(self):
        api, worker = self.contract["api"], self.contract["worker"]
        baseline = {role: self.observe_process(role) for role in ROLES}
        self.expect(baseline["api"]["serviceAccount"] != baseline["worker"]["serviceAccount"],
                    "api and worker share a ServiceAccount")
        self.expect(baseline["api"]["settings"] != baseline["worker"]["settings"],
                    "api and worker settings are not independent")
        api_pod = baseline["api"]["pod"]
        slices = self.kube_json(["--namespace", APP_NAMESPACE, "get", "endpointslices",
                                 "--selector", "kubernetes.io/service-name=openmettle-api",
                                 "--output=json"])["items"]
        ready_targets = [e["targetRef"]["name"] for s in slices for e in s.get("endpoints", [])
                         if e.get("conditions", {}).get("ready")]
        self.expect(ready_targets == [api_pod], f"API Service endpoints: {ready_targets}")
        self.passed("API Service routes to ready API pod", endpoints=ready_targets)

        # Stop every worker while continuously probing the API.
        forward = PortForward(self.kubectl, self.env, f"pod/{api_pod}", api["port"])
        results: list = []
        stop = threading.Event()

        def probe():
            while not stop.is_set():
                results.append(http_get(forward.port, api["readinessPath"]))
                time.sleep(0.25)
        prober = threading.Thread(target=probe, daemon=True)
        prober.start()
        try:
            worker_exits = self.scale_down_observing_exit("worker")
            time.sleep(10)  # several kubelet readiness periods with no worker
        finally:
            stop.set()
            prober.join(timeout=10)
            forward.close()
        failures = [r for r in results if r != (200, "ready\n")]
        self.expect(len(results) >= 20 and not failures,
                    f"API readiness during worker stop: {len(failures)} failures of {len(results)}")
        deployment = self.deployment("worker")
        self.expect(deployment["spec"]["replicas"] == 0
                    and deployment["status"].get("replicas", 0) == 0, "worker did not reach zero")
        api_now = self.pods("api")
        self.expect([p["metadata"]["name"] for p in api_now] == [api_pod], "API pod was replaced")
        api_ready = self.deployment("api")["status"].get("readyReplicas")
        self.expect(api_ready == 1, "API Deployment lost readiness with worker at zero")
        self.observe_process("api")
        self.passed("API survives worker scaled to zero", worker_exit_codes=worker_exits,
                    api_readiness_probes=len(results), api_ready_replicas=api_ready)

        # Independent scaling: worker to 2 while the API stays at 1.
        self.scale("worker", 2)
        self.kube("--namespace", APP_NAMESPACE, "rollout", "status", "deployment/openmettle-worker",
                  "--timeout=180s", timeout=210)
        counts = {role: self.deployment(role)["status"].get("readyReplicas") for role in ROLES}
        self.expect(counts == {"api": 1, "worker": 2}, f"independent scale not observed: {counts}")
        self.observe_process("worker")
        self.passed("independent scaling", ready_replicas=counts)

        # Database loss affects readiness, not liveness; recovery needs no restart.
        self.scale("postgres", 0, namespace=DB_NAMESPACE, name="postgres")
        forward = PortForward(self.kubectl, self.env, f"pod/{api_pod}", api["port"])
        try:
            self.wait_for("API readiness 503 without PostgreSQL",
                          lambda: http_get(forward.port, api["readinessPath"])[0] == 503, timeout=90)
            self.expect(http_get(forward.port, api["livenessPath"]) == (200, "ok\n"),
                        "API liveness failed while PostgreSQL was down")
            for role in ROLES:
                self.wait_for(f"{role} pods NotReady", lambda role=role: all(
                    {c["type"]: c["status"] for c in p["status"].get("conditions", [])}.get("Ready")
                    == "False" for p in self.pods(role)), timeout=60)
            self.scale("postgres", 1, namespace=DB_NAMESPACE, name="postgres")
            self.kube("--namespace", DB_NAMESPACE, "rollout", "status", "deployment/postgres",
                      "--timeout=300s", timeout=330)
            self.wait_for("API readiness recovery",
                          lambda: http_get(forward.port, api["readinessPath"]) == (200, "ready\n"),
                          timeout=90)
        finally:
            forward.close()
        for role in ROLES:
            self.kube("--namespace", APP_NAMESPACE, "rollout", "status",
                      f"deployment/openmettle-{role}", "--timeout=120s", timeout=150)
            restarts = [c.get("restartCount") for p in self.pods(role)
                        for c in p["status"]["containerStatuses"]]
            self.expect(restarts and all(r == 0 for r in restarts),
                        f"{role} restarted during database loss: {restarts}")
        self.passed("database loss gates readiness only; recovery without restart")

        # Clean shutdown of both processes.
        worker_exits = self.scale_down_observing_exit("worker")
        api_exits = self.scale_down_observing_exit("api")
        self.passed("clean SIGTERM shutdown", worker=worker_exits, api=api_exits)
        self.report["contract"] = {role: {k: self.contract[role][k] for k in (
            "serviceAccountName", "requests", "port")} for role in ROLES}
        self.report["result"] = "passed"

    def diagnostics(self):
        if not self.kubeconfig.exists():
            return
        for args in (["get", "pods", "--all-namespaces", "--output=wide"],
                     ["--namespace", APP_NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"],
                     ["--namespace", APP_NAMESPACE, "logs", "--selector",
                      "app.kubernetes.io/name", "--all-containers", "--prefix", "--tail=100"],
                     ["--namespace", DB_NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"]):
            result = self.kube(*args, check=False, timeout=60)
            print(result.stdout[-6000:] + result.stderr[-2000:], file=sys.stderr)

    def cleanup(self):
        commands = []
        if self.cluster_attempted:
            _log(f"deleting kind cluster {self.name}")
            commands.append((["kind", "delete", "cluster", "--name", self.name,
                              "--kubeconfig", str(self.kubeconfig)], 300))
        for image in self.built_images:
            commands.append((["docker", "image", "rm", image], 120))
        failures = []
        for command, timeout in commands:
            try:
                result = self.run(command, check=False, timeout=timeout)
                if result.returncode:
                    failures.append(f"{' '.join(command)}: exit {result.returncode}")
            except (Refusal, QualificationFailure, subprocess.TimeoutExpired, OSError) as exc:
                failures.append(f"{' '.join(command)}: {type(exc).__name__}")
        return failures


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tools-dir", type=Path, help="directory from install-tools.sh")
    parser.add_argument("--report", type=Path, help="write observed (non-secret) results as JSON")
    args = parser.parse_args(argv)
    try:
        contract = load_contract()
    except ContractError as exc:
        print(f"contract error: {exc}", file=sys.stderr)
        return 2
    workdir = Path(tempfile.mkdtemp(prefix="openmettle-k8s-qual-"))
    try:
        qualification = Qualification(contract, dict(os.environ),
                                      args.tools_dir.resolve() if args.tools_dir else None, workdir)
        qualification.preflight()
    except (Refusal, QualificationFailure) as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    status = 1
    try:
        qualification.build_images()
        qualification.create_cluster()
        qualification.deploy()
        qualification.scenario()
        status = 0
    except (QualificationFailure, Refusal, subprocess.TimeoutExpired) as exc:
        qualification.report["result"] = "failed"
        qualification.report["error"] = str(exc)
        print(f"qualification failed: {exc}", file=sys.stderr)
        qualification.diagnostics()
    finally:
        cleanup_failures = qualification.cleanup()
        if cleanup_failures:
            status = 1
            qualification.report["result"] = "failed"
            qualification.report["cleanup_errors"] = cleanup_failures
            for failure in cleanup_failures:
                _log(f"cleanup failed: {failure}")
            _log(f"temporary kubeconfig retained for recovery in {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
        if args.report:
            args.report.write_text(json.dumps(qualification.report, indent=2) + "\n")
    return status


if __name__ == "__main__":
    sys.exit(main())
