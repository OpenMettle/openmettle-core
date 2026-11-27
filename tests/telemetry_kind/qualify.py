#!/usr/bin/env python3
"""Qualify the V1-29 telemetry contract v1 on an ephemeral kind cluster (ADR 0028).

Test fixture only: this is not an installer, Helm chart or deployment manifest. The harness
creates a uniquely named kind cluster classified `dev`, uses a temporary kubeconfig, builds
local `openmettle-api`, `openmettle-worker` and `openmettle-gateway` images without publishing them, deploys pinned
PostgreSQL, Grafana Alloy and Prometheus fixtures with an ephemeral synthetic TLS CA, and
deletes only the cluster and image tags it created.

Assertions verify live cluster, OTLP/HTTPS trace+metrics ingestion, Prometheus translation and
alert rule evaluation, redaction / inbound traceparent ignoring, and collector-outage
resilience (probes stay 200 OK with zero restarts while `telemetry.dropped` is logged and
`OpenMettleTelemetryDropsDetected` enters pending/firing).

Requires Python 3.10+, docker, openssl, and the pinned kind/kubectl from
tests/kubernetes/install-tools.sh.
"""
from __future__ import annotations

import argparse
import contextlib
import http.client
import importlib.util
import json
import os
import queue
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TELEMETRY_CONTRACT = ROOT / "contracts" / "telemetry" / "v1.json"
ALERTS_FILE = ROOT / "contracts" / "telemetry" / "alerts-v1.yaml"
K8S_QUALIFY_PATH = ROOT / "tests" / "kubernetes" / "qualify.py"


def _load_k8s_qualify():
    spec = importlib.util.spec_from_file_location("openmettle_k8s_qualify", K8S_QUALIFY_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load shared helpers from {K8S_QUALIFY_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_k8s = _load_k8s_qualify()

OPT_IN_VAR = _k8s.OPT_IN_VAR
OPT_IN_VALUE = _k8s.OPT_IN_VALUE
DOCKER_CONTEXT_VAR = _k8s.DOCKER_CONTEXT_VAR
KIND_VERSION = _k8s.KIND_VERSION
KUBECTL_VERSION = _k8s.KUBECTL_VERSION
NODE_IMAGE = _k8s.NODE_IMAGE
POSTGRES_IMAGE = _k8s.POSTGRES_IMAGE
APP_NAMESPACE = _k8s.APP_NAMESPACE
DB_NAMESPACE = _k8s.DB_NAMESPACE
FINALIZER = _k8s.FINALIZER
ROLES = _k8s.ROLES
FIXTURE_SETTINGS = _k8s.FIXTURE_SETTINGS
IMAGE_USER = _k8s.IMAGE_USER
STRIPPED_ENV = _k8s.STRIPPED_ENV

Refusal = _k8s.Refusal
ContractError = _k8s.ContractError
QualificationFailure = _k8s.QualificationFailure
load_contract = _k8s.load_contract
database_url = _k8s.database_url
child_environment = _k8s.child_environment
check_opt_in = _k8s.check_opt_in
check_tools = _k8s.check_tools
check_docker_context = _k8s.check_docker_context
check_cluster_identity = _k8s.check_cluster_identity
Runner = _k8s.Runner

# Multi-arch Docker Hub index digests resolved 2026-11-20. Test fixtures only; not distributed.
PROMETHEUS_IMAGE = (
    "docker.io/prom/prometheus:v3.5.0"
    "@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
)
ALLOY_IMAGE = (
    "docker.io/grafana/alloy:v1.10.0"
    "@sha256:1bc130e909116a4bf950eb5187a346007d3b796f96832b529acb14a64e41230f"
)
CLUSTER_NAME = re.compile(r"openmettle-dev-telemetry-[0-9a-f]{8}")
TELEMETRY_NAMESPACE = "openmettle-qualification-telemetry"
ALLOY_HOST = f"alloy.{TELEMETRY_NAMESPACE}.svc.cluster.local"
PROMETHEUS_HOST = f"prometheus.{TELEMETRY_NAMESPACE}.svc.cluster.local"
RELAY_HOST = f"otlp-delay-relay.{TELEMETRY_NAMESPACE}.svc.cluster.local"
ALLOY_OTLP_PORT = 4318
ALLOY_ADMIN_PORT = 12345
PROMETHEUS_PORT = 9090
RELAY_PORT = 9091
RELAY_DELAY_MS = 1500
OTLP_CA_MOUNT_DIR = "/etc/openmettle/otlp-ca"
OTLP_CA_FILE = f"{OTLP_CA_MOUNT_DIR}/ca.crt"
OTLP_PRIVATE_RANGES = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

UUIDV4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
# Synthetic canary values sent in a single unmatched request to prove inbound traceparent
# ignoring and redaction across logs, traces, and metrics.
CANARY_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
CANARY_TRACEPARENT = f"00-{CANARY_TRACE_ID}-00f067aa0ba902b7-01"
CANARY_QUERY_SECRET = "openmettle-synthetic-query-secret-never-log"
CANARY_BEARER_TOKEN = "openmettle-synthetic-bearer-token-never-log"
GATEWAY_PROBE_REQUEST_ID = "00000000-0000-4000-8000-000000000001"
EXPECTED_ALERTS = (
    "OpenMettleApiHighServerErrorRatio",
    "OpenMettleDatabaseReadinessFailing",
    "OpenMettleTelemetryDropsDetected",
    "OpenMettleProviderTransportFailures",
    "OpenMettleGatewayFailuresDetected",
    "OpenMettleRunQueueHighAge",
    "OpenMettleStorageQuotaDriftDetected",
    "OpenMettleBackupFailedOrOverdue",
)

OPENSSL_CONFIG = f"""[req]
distinguished_name = subject
prompt = no
[subject]
CN = OpenMettle Telemetry qualification
[authority]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign
subjectKeyIdentifier = hash
[collector]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:{ALLOY_HOST}
authorityKeyIdentifier = keyid
"""


# --- Telemetry contract and fixture rendering --------------------------------------------

def load_telemetry_contract(path: Path = TELEMETRY_CONTRACT) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ContractError(f"{path.name}: unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError("telemetry contract must be a JSON object")
    if data.get("contract_version") != "1.0.0":
        raise ContractError("telemetry contract_version must be 1.0.0")
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise ContractError("telemetry contract missing policy")
    if policy.get("prometheus_translation") != "UnderscoreEscapingWithSuffixes":
        raise ContractError("telemetry contract must specify UnderscoreEscapingWithSuffixes")
    if not isinstance(policy.get("disallowed_metric_label_substrings"), list):
        raise ContractError("telemetry contract missing disallowed_metric_label_substrings")
    metrics = data.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        raise ContractError("telemetry contract missing metrics")
    return data


def load_alerts_text(path: Path = ALERTS_FILE) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractError(f"{path.name}: unreadable: {exc}") from exc
    for alert_name in EXPECTED_ALERTS:
        if f"alert: {alert_name}" not in text:
            raise ContractError(f"{path.name}: missing alert rule {alert_name}")
    return text


def render_prometheus_config() -> str:
    # Rule group openmettle-core-v1 in alerts-v1.yaml sets its own `interval: 30s`.
    return (
        "# Rule group openmettle-core-v1 evaluates every 30s (declared in alerts-v1.yaml).\n"
        "otlp:\n"
        "  translation_strategy: UnderscoreEscapingWithSuffixes\n"
        "rule_files:\n"
        "  - /etc/prometheus/rules/alerts-v1.yaml\n"
    )


def render_alloy_config() -> str:
    return (
        'otelcol.receiver.otlp "default" {\n'
        "  http {\n"
        f'    endpoint = "0.0.0.0:{ALLOY_OTLP_PORT}"\n'
        "    tls {\n"
        '      cert_file = "/etc/alloy/tls/tls.crt"\n'
        '      key_file  = "/etc/alloy/tls/tls.key"\n'
        "    }\n"
        "  }\n"
        "  output {\n"
        "    metrics = [otelcol.exporter.otlphttp.prometheus.input]\n"
        "    traces  = [otelcol.exporter.debug.traces.input]\n"
        "  }\n"
        "}\n"
        "\n"
        'otelcol.exporter.otlphttp "prometheus" {\n'
        "  client {\n"
        f'    endpoint    = "http://{RELAY_HOST}:{RELAY_PORT}/api/v1/otlp"\n'
        '    compression = "none"\n'
        "    tls {\n"
        "      insecure = true\n"
        "    }\n"
        "  }\n"
        "  sending_queue {\n"
        "    enabled       = true\n"
        "    num_consumers = 1\n"
        "  }\n"
        "}\n"
        "\n"
        'otelcol.exporter.debug "traces" {\n'
        '  verbosity = "detailed"\n'
        "}\n"
    )


def generate_collector_tls(workdir: Path) -> dict[str, str]:
    """Generate an ephemeral RSA-2048 CA and server certificate for ALLOY_HOST.

    The CA private key is unlinked immediately after signing the collector certificate, and the
    entire temporary directory is removed in `finally` before returning PEM strings.
    """
    tls_dir = workdir / "collector-tls"
    tls_dir.mkdir(mode=0o700)
    config = tls_dir / "openssl.cnf"
    ca_key = tls_dir / "ca-key.pem"
    ca_crt = tls_dir / "ca-crt.pem"
    srv_key = tls_dir / "tls-key.pem"
    srv_csr = tls_dir / "tls.csr"
    srv_crt = tls_dir / "tls-crt.pem"
    config.write_text(OPENSSL_CONFIG, encoding="utf-8")

    def openssl(*arguments: str) -> None:
        try:
            subprocess.run(
                ["openssl", *arguments],
                check=True,
                timeout=60,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise Refusal("required runner tool missing: openssl") from exc
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise QualificationFailure(f"openssl failed during synthetic CA setup: {exc}") from exc

    key_cmd = ("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out")
    try:
        openssl(*key_cmd, str(ca_key))
        openssl(
            "req", "-new", "-x509", "-key", str(ca_key), "-sha256", "-days", "2",
            "-config", str(config), "-extensions", "authority",
            "-subj", "/CN=OpenMettle Telemetry qualification CA",
            "-out", str(ca_crt),
        )
        openssl(*key_cmd, str(srv_key))
        openssl(
            "req", "-new", "-key", str(srv_key), "-config", str(config),
            "-subj", f"/CN={ALLOY_HOST}",
            "-out", str(srv_csr),
        )
        openssl(
            "x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt),
            "-CAkey", str(ca_key), "-set_serial", "2", "-sha256", "-days", "2",
            "-extfile", str(config), "-extensions", "collector",
            "-out", str(srv_crt),
        )
        ca_key.unlink(missing_ok=True)
        return {
            "ca_crt": ca_crt.read_text(encoding="utf-8"),
            "tls_crt": srv_crt.read_text(encoding="utf-8"),
            "tls_key": srv_key.read_text(encoding="utf-8"),
        }
    finally:
        shutil.rmtree(tls_dir, ignore_errors=True)


def render_manifests(
    contract: dict,
    images: dict,
    passwords: dict,
    tls: dict[str, str],
    alerts_yaml: str,
    run_id: str,
) -> dict:
    """Return a kubectl List with DB, Prometheus, Alloy, and OTLP-enabled API/worker/gateway."""
    labels = {"openmettle.dev/environment": "dev", "openmettle.dev/qualification-run": run_id}
    items = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": APP_NAMESPACE,
                "labels": {
                    **labels,
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/enforce-version": "latest",
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": DB_NAMESPACE, "labels": labels},
        },
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": TELEMETRY_NAMESPACE, "labels": labels},
        },
    ]

    # PostgreSQL fixture (same synthetic pattern as tests/kubernetes/qualify.py)
    roles_sql = "".join(
        f"CREATE ROLE openmettle_{role} LOGIN PASSWORD '{passwords[role]}';\n" for role in ROLES
    )
    items += [
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "type": "Opaque",
            "metadata": {"name": "postgres-fixture", "namespace": DB_NAMESPACE},
            "stringData": {"admin-password": passwords["admin"], "roles.sql": roles_sql},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "postgres", "namespace": DB_NAMESPACE},
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": {"app.kubernetes.io/name": "postgres"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "postgres"}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "enableServiceLinks": False,
                        "containers": [{
                            "name": "postgres",
                            "image": POSTGRES_IMAGE,
                            "imagePullPolicy": "IfNotPresent",
                            "env": [
                                {"name": "POSTGRES_USER", "value": "fixture_admin"},
                                {"name": "POSTGRES_DB", "value": "fixture"},
                                {
                                    "name": "POSTGRES_PASSWORD",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": "postgres-fixture",
                                            "key": "admin-password",
                                        }
                                    },
                                },
                            ],
                            "ports": [{"name": "postgres", "containerPort": 5432}],
                            "readinessProbe": {
                                "exec": {
                                    "command": [
                                        "pg_isready", "-h", "127.0.0.1",
                                        "-U", "fixture_admin", "-d", "fixture",
                                    ]
                                },
                                "periodSeconds": 2,
                                "failureThreshold": 2,
                            },
                            "volumeMounts": [
                                {"name": "data", "mountPath": "/var/lib/postgresql"},
                                {
                                    "name": "init",
                                    "mountPath": "/docker-entrypoint-initdb.d",
                                    "readOnly": True,
                                },
                            ],
                        }],
                        "volumes": [
                            {"name": "data", "emptyDir": {}},
                            {
                                "name": "init",
                                "secret": {
                                    "secretName": "postgres-fixture",
                                    "items": [{"key": "roles.sql", "path": "roles.sql"}],
                                },
                            },
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "postgres", "namespace": DB_NAMESPACE},
            "spec": {
                "selector": {"app.kubernetes.io/name": "postgres"},
                "ports": [{"name": "postgres", "port": 5432, "targetPort": "postgres"}],
            },
        },
    ]

    # Prometheus + Grafana Alloy fixtures in TELEMETRY_NAMESPACE
    items += [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "prometheus-config", "namespace": TELEMETRY_NAMESPACE},
            "data": {"prometheus.yml": render_prometheus_config()},
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "prometheus-rules", "namespace": TELEMETRY_NAMESPACE},
            "data": {"alerts-v1.yaml": alerts_yaml},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "prometheus", "namespace": TELEMETRY_NAMESPACE},
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": {"app.kubernetes.io/name": "prometheus"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "prometheus"}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "enableServiceLinks": False,
                        "securityContext": {"fsGroup": 65534},
                        "containers": [{
                            "name": "prometheus",
                            "image": PROMETHEUS_IMAGE,
                            "imagePullPolicy": "IfNotPresent",
                            "args": [
                                "--config.file=/etc/prometheus/prometheus.yml",
                                "--storage.tsdb.path=/prometheus",
                                "--web.enable-otlp-receiver",
                            ],
                            "ports": [{"name": "http", "containerPort": PROMETHEUS_PORT}],
                            "readinessProbe": {
                                "httpGet": {"path": "/-/ready", "port": "http"},
                                "periodSeconds": 2,
                                "failureThreshold": 3,
                            },
                            "volumeMounts": [
                                {
                                    "name": "config",
                                    "mountPath": "/etc/prometheus/prometheus.yml",
                                    "subPath": "prometheus.yml",
                                    "readOnly": True,
                                },
                                {
                                    "name": "rules",
                                    "mountPath": "/etc/prometheus/rules",
                                    "readOnly": True,
                                },
                                {"name": "data", "mountPath": "/prometheus"},
                            ],
                        }],
                        "volumes": [
                            {"name": "config", "configMap": {"name": "prometheus-config"}},
                            {"name": "rules", "configMap": {"name": "prometheus-rules"}},
                            {"name": "data", "emptyDir": {}},
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "prometheus", "namespace": TELEMETRY_NAMESPACE},
            "spec": {
                "selector": {"app.kubernetes.io/name": "prometheus"},
                "ports": [{"name": "http", "port": PROMETHEUS_PORT, "targetPort": "http"}],
            },
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "otlp-delay-relay", "namespace": TELEMETRY_NAMESPACE},
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": {"app.kubernetes.io/name": "otlp-delay-relay"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "otlp-delay-relay"}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "enableServiceLinks": False,
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 65532,
                            "runAsGroup": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "containers": [{
                            "name": "relay",
                            "image": images["relay"],
                            "imagePullPolicy": "Never",
                            "env": [
                                {"name": "RELAY_BIND", "value": f"0.0.0.0:{RELAY_PORT}"},
                                {
                                    "name": "UPSTREAM_ADDR",
                                    "value": f"{PROMETHEUS_HOST}:{PROMETHEUS_PORT}",
                                },
                            ],
                            "ports": [{"name": "http", "containerPort": RELAY_PORT}],
                            "readinessProbe": {
                                "httpGet": {"path": "/healthz", "port": "http"},
                                "periodSeconds": 2,
                                "failureThreshold": 3,
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "otlp-delay-relay", "namespace": TELEMETRY_NAMESPACE},
            "spec": {
                "selector": {"app.kubernetes.io/name": "otlp-delay-relay"},
                "ports": [{"name": "http", "port": RELAY_PORT, "targetPort": "http"}],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "alloy-config", "namespace": TELEMETRY_NAMESPACE},
            "data": {"config.alloy": render_alloy_config()},
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "type": "kubernetes.io/tls",
            "metadata": {"name": "alloy-tls", "namespace": TELEMETRY_NAMESPACE},
            "stringData": {"tls.crt": tls["tls_crt"], "tls.key": tls["tls_key"]},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "alloy", "namespace": TELEMETRY_NAMESPACE},
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": {"app.kubernetes.io/name": "alloy"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "alloy"}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "enableServiceLinks": False,
                        "containers": [{
                            "name": "alloy",
                            "image": ALLOY_IMAGE,
                            "imagePullPolicy": "IfNotPresent",
                            "args": [
                                "run",
                                "/etc/alloy/config.alloy",
                                "--stability.level=experimental",
                                f"--server.http.listen-addr=0.0.0.0:{ALLOY_ADMIN_PORT}",
                                "--storage.path=/var/lib/alloy/data",
                                "--disable-reporting",
                            ],
                            "ports": [
                                {"name": "otlp-http", "containerPort": ALLOY_OTLP_PORT},
                                {"name": "http-metrics", "containerPort": ALLOY_ADMIN_PORT},
                            ],
                            "readinessProbe": {
                                "httpGet": {"path": "/-/ready", "port": "http-metrics"},
                                "periodSeconds": 2,
                                "failureThreshold": 3,
                            },
                            "volumeMounts": [
                                {
                                    "name": "config",
                                    "mountPath": "/etc/alloy/config.alloy",
                                    "subPath": "config.alloy",
                                    "readOnly": True,
                                },
                                {"name": "tls", "mountPath": "/etc/alloy/tls", "readOnly": True},
                                {"name": "data", "mountPath": "/var/lib/alloy/data"},
                            ],
                        }],
                        "volumes": [
                            {"name": "config", "configMap": {"name": "alloy-config"}},
                            {"name": "tls", "secret": {"secretName": "alloy-tls"}},
                            {"name": "data", "emptyDir": {}},
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "alloy", "namespace": TELEMETRY_NAMESPACE},
            "spec": {
                "selector": {"app.kubernetes.io/name": "alloy"},
                "ports": [
                    {"name": "otlp-http", "port": ALLOY_OTLP_PORT, "targetPort": "otlp-http"},
                    {"name": "http-metrics", "port": ALLOY_ADMIN_PORT, "targetPort": "http-metrics"},
                ],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "alloy-ca", "namespace": APP_NAMESPACE},
            "data": {"ca.crt": tls["ca_crt"]},
        },
    ]

    # OTLP-enabled API, worker and gateway deployments under restricted PSS
    traces_url = f"https://{ALLOY_HOST}:{ALLOY_OTLP_PORT}/v1/traces"
    metrics_url = f"https://{ALLOY_HOST}:{ALLOY_OTLP_PORT}/v1/metrics"
    for role in ROLES:
        spec = contract[role]
        prefix = spec["configurationPrefix"]
        name = f"openmettle-{role}"
        selector = {"app.kubernetes.io/name": name}
        env = [
            {"name": f"{prefix}BIND", "value": f"0.0.0.0:{spec['port']}"},
            {
                "name": f"{prefix}DATABASE_URL",
                "valueFrom": {"secretKeyRef": {"name": f"{name}-database", "key": "url"}},
            },
            *[{"name": prefix + k, "value": v} for k, v in FIXTURE_SETTINGS[role].items()],
            *([{"name": f"{prefix}LOG_LEVEL", "value": "debug"}] if role == "gateway" else []),
            {"name": f"{prefix}OTLP_TRACES_ENDPOINT", "value": traces_url},
            {"name": f"{prefix}OTLP_METRICS_ENDPOINT", "value": metrics_url},
            {"name": f"{prefix}OTLP_CA_FILE", "value": OTLP_CA_FILE},
            {"name": f"{prefix}OTLP_PRIVATE_RANGES", "value": OTLP_PRIVATE_RANGES},
        ]
        items += [
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "type": "Opaque",
                "metadata": {"name": f"{name}-database", "namespace": APP_NAMESPACE},
                "stringData": {"url": database_url(role, passwords[role])},
            },
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": spec["serviceAccountName"], "namespace": APP_NAMESPACE},
                "automountServiceAccountToken": spec["automountServiceAccountToken"],
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": name, "namespace": APP_NAMESPACE, "labels": selector},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": selector},
                    "template": {
                        "metadata": {"labels": {**selector, "app.kubernetes.io/component": role}},
                        "spec": {
                            "serviceAccountName": spec["serviceAccountName"],
                            "automountServiceAccountToken": spec["automountServiceAccountToken"],
                            "enableServiceLinks": False,
                            "terminationGracePeriodSeconds": 15,
                            "securityContext": {
                                "runAsNonRoot": True,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [{
                                "name": role,
                                "image": images[role],
                                "imagePullPolicy": "Never",
                                "ports": [{"name": "http", "containerPort": spec["port"]}],
                                "env": env,
                                "resources": {"requests": dict(spec["requests"])},
                                "readinessProbe": {
                                    "httpGet": {"path": spec["readinessPath"], "port": "http"},
                                    "periodSeconds": 2,
                                    "failureThreshold": 2,
                                    "timeoutSeconds": 3,
                                },
                                "livenessProbe": {
                                    "httpGet": {"path": spec["livenessPath"], "port": "http"},
                                    "periodSeconds": 5,
                                    "failureThreshold": 3,
                                    "timeoutSeconds": 3,
                                },
                                "volumeMounts": [{
                                    "name": "otlp-ca",
                                    "mountPath": OTLP_CA_MOUNT_DIR,
                                    "readOnly": True,
                                }],
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                            }],
                            "volumes": [{
                                "name": "otlp-ca",
                                "configMap": {"name": "alloy-ca"},
                            }],
                        },
                    },
                },
            },
        ]
    return {"apiVersion": "v1", "kind": "List", "items": items}


# --- Contract series validation & Alloy/Prometheus parsers -------------------------------

def _allowed_series_catalog(telemetry_contract: dict) -> dict[str, dict[str, set[str]]]:
    """Map Prometheus metric series names to allowed normalized label -> closed value sets."""
    catalog: dict[str, dict[str, set[str]]] = {}
    for metric in telemetry_contract["metrics"]:
        prom_name = metric["prometheus_name"]
        labels = {
            k.replace(".", "_"): set(values) for k, values in metric.get("labels", {}).items()
        }
        if metric["kind"] == "histogram":
            bucket_values = {f"{b:g}" for b in metric["buckets"]} | {"+Inf"}
            catalog[f"{prom_name}_bucket"] = {**labels, "le": bucket_values}
            catalog[f"{prom_name}_sum"] = dict(labels)
            catalog[f"{prom_name}_count"] = dict(labels)
        else:
            catalog[prom_name] = dict(labels)
    return catalog


def validate_prometheus_series(series_list: list[dict], telemetry_contract: dict) -> dict:
    """Validate every observed `openmettle_*` series against telemetry contract v1.

    Checks:
    - Every metric name is declared by contracts/telemetry/v1.json (with Prometheus translation).
    - Zero label names contain any disallowed substring from the contract.
    - Every label name is either `__name__`, `job`, `instance`, or a declared label for that metric.
    - `job` is `openmettle-api`, `openmettle-worker`, or `openmettle-gateway` and `instance` is a valid UUIDv4.
    - Every metric-specific label value belongs to the contract's closed enum set.
    """
    disallowed = [s.lower() for s in telemetry_contract["policy"]["disallowed_metric_label_substrings"]]
    catalog = _allowed_series_catalog(telemetry_contract)
    allowed_jobs = {f"openmettle-{role}" for role in ROLES}
    instances_by_job: dict[str, set[str]] = {}
    observed_names: set[str] = set()

    for sample in series_list:
        labels = sample.get("metric") or {}
        name = labels.get("__name__", "")
        if name not in catalog:
            raise QualificationFailure(f"undeclared openmettle Prometheus series: {name}")
        observed_names.add(name)
        expected_labels = catalog[name]
        for label_name, label_value in labels.items():
            if label_name == "__name__":
                continue
            lowered = label_name.lower()
            for forbidden in disallowed:
                if forbidden in lowered:
                    raise QualificationFailure(
                        f"series {name} contains disallowed label {label_name} (matched '{forbidden}')"
                    )
            if label_name == "job":
                if label_value not in allowed_jobs:
                    raise QualificationFailure(f"series {name} has unexpected job label: {label_value}")
                continue
            if label_name == "instance":
                if not UUIDV4_RE.fullmatch(label_value):
                    raise QualificationFailure(
                        f"series {name} has non-UUIDv4 instance label: {label_value}"
                    )
                continue
            if label_name not in expected_labels:
                raise QualificationFailure(
                    f"series {name} contains undeclared label {label_name}"
                )
            if label_name == "le":
                if label_value != "+Inf":
                    try:
                        normalized = f"{float(label_value):g}"
                    except ValueError as exc:
                        raise QualificationFailure(
                            f"series {name} has non-numeric le label {label_value}"
                        ) from exc
                    if normalized not in expected_labels["le"]:
                        raise QualificationFailure(
                            f"series {name} has undeclared histogram bucket le={label_value}"
                        )
            elif label_value not in expected_labels[label_name]:
                raise QualificationFailure(
                    f"series {name} label {label_name}={label_value!r} outside contract enum"
                )
        job = labels.get("job")
        instance = labels.get("instance")
        if not job or not instance:
            raise QualificationFailure(f"series {name} missing job or instance resource label")
        missing = sorted(set(expected_labels) - set(labels))
        if missing:
            raise QualificationFailure(
                f"series {name} missing declared label(s): {', '.join(missing)}"
            )
        instances_by_job.setdefault(job, set()).add(instance)

    return {
        "series_count": len(series_list),
        "metric_names": sorted(observed_names),
        "instances_by_job": {k: sorted(v) for k, v in sorted(instances_by_job.items())},
    }


def validate_worker_quota_drift_baseline(
    series_list: list[dict], telemetry_contract: dict
) -> dict[str, dict[str, float]]:
    """Require every live worker instance to expose exact bijective equality with all declared
    zero-initialized `openmettle_storage_quota_drift_total` outcome series before the first
    hourly drift verification sweep.
    """
    drift_metric = next(
        (
            m
            for m in telemetry_contract.get("metrics", [])
            if m.get("prometheus_name") == "openmettle_storage_quota_drift_total"
        ),
        None,
    )
    if drift_metric is None:
        raise ContractError("telemetry contract missing openmettle_storage_quota_drift_total")
    expected_outcomes = set(drift_metric.get("labels", {}).get("outcome", []))
    if not expected_outcomes:
        raise ContractError("telemetry contract missing outcome labels for quota drift")

    if not series_list:
        raise QualificationFailure(
            "missing openmettle_storage_quota_drift_total worker baseline series"
        )

    expected_label_keys = {"__name__", "job", "instance", "outcome"}
    by_instance: dict[str, dict[str, float]] = {}
    for sample in series_list:
        labels = sample.get("metric") or {}
        name = labels.get("__name__", "")
        if name != "openmettle_storage_quota_drift_total":
            raise QualificationFailure(f"unexpected series in quota drift baseline: {name}")
        extra_keys = sorted(set(labels) - expected_label_keys)
        if extra_keys:
            raise QualificationFailure(
                f"worker quota drift series contains unexpected label(s): {', '.join(extra_keys)}"
            )
        job = labels.get("job")
        if job != "openmettle-worker":
            raise QualificationFailure(
                f"unexpected job in worker quota drift baseline: {job!r}"
            )
        instance = labels.get("instance")
        if not instance or not UUIDV4_RE.fullmatch(instance):
            raise QualificationFailure(
                f"worker quota drift series has invalid instance label: {instance!r}"
            )
        outcome = labels.get("outcome")
        if outcome not in expected_outcomes:
            raise QualificationFailure(
                f"worker quota drift series has undeclared outcome={outcome!r}"
            )
        raw_value = sample.get("value")
        if not isinstance(raw_value, list) or len(raw_value) < 2:
            raise QualificationFailure(
                f"worker quota drift series outcome={outcome!r} missing numeric sample value"
            )
        try:
            value = float(raw_value[1])
        except (TypeError, ValueError) as exc:
            raise QualificationFailure(
                f"worker quota drift series outcome={outcome!r} has non-numeric value {raw_value[1]!r}"
            ) from exc
        if value != 0.0:
            raise QualificationFailure(
                f"expected zero-initialized worker quota drift baseline for outcome={outcome!r}, got {value}"
            )
        inst_outcomes = by_instance.setdefault(instance, {})
        if outcome in inst_outcomes:
            raise QualificationFailure(
                f"duplicate worker quota drift series for instance={instance} outcome={outcome!r}"
            )
        inst_outcomes[outcome] = value

    for instance, outcomes in sorted(by_instance.items()):
        missing = sorted(expected_outcomes - set(outcomes))
        extra = sorted(set(outcomes) - expected_outcomes)
        if missing or extra:
            raise QualificationFailure(
                f"worker instance {instance} quota drift baseline mismatch: "
                f"missing={missing}, extra={extra}"
            )
    return by_instance


def parse_alloy_accepted_spans(metrics_text: str) -> float:
    """Sum `otelcol_receiver_accepted_spans[_total]` samples from Alloy `/metrics`."""
    total = 0.0
    pattern = re.compile(
        r"^otelcol_receiver_accepted_spans(?:_total)?(?:\{[^}]*\})?\s+([0-9.eE+-]+)$"
    )
    for line in metrics_text.splitlines():
        match = pattern.match(line.strip())
        if match:
            total += float(match.group(1))
    return total


def parse_gateway_request_logs(logs: str) -> list[dict]:
    """Extract DEBUG `http.request.completed` JSON entries for unauthenticated gateway probes."""
    matches = []
    for line in logs.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        request_id = entry.get("request_id")
        duration_us = entry.get("duration_us")
        if (
            entry.get("level") == "DEBUG"
            and entry.get("event") == "http.request.completed"
            and entry.get("http.route") == "/v1/chat/completions"
            and entry.get("http.request.method") == "POST"
            and entry.get("http.response.status_code") == 401
            and isinstance(request_id, str)
            and UUIDV4_RE.fullmatch(request_id)
            and request_id != GATEWAY_PROBE_REQUEST_ID
            and isinstance(duration_us, int)
            and not isinstance(duration_us, bool)
        ):
            matches.append(entry)
    return matches


def _pb_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _pb_len(field: int, payload: bytes) -> bytes:
    return _pb_varint((field << 3) | 2) + _pb_varint(len(payload)) + payload


def _pb_str(field: int, text: str) -> bytes:
    return _pb_len(field, text.encode("utf-8"))


def _pb_kv(key: str, value: str) -> bytes:
    # KeyValue { 1: key (string), 2: AnyValue { 1: string_value (string) } }
    any_val = _pb_str(1, value)
    return _pb_str(1, key) + _pb_len(2, any_val)


def encode_otlp_slow_exit_counter(
    instance_id: str,
    outcome: str,
    start_time_unix_nano: int,
    time_unix_nano: int,
    value: int,
    *,
    service_name: str = "openmettle-worker",
) -> bytes:
    """Encode a valid OTLP ExportMetricsServiceRequest protobuf for `openmettle.runs.queue.slow_exits`."""
    # NumberDataPoint: 7=attributes, 2=start_time_unix_nano (fixed64), 3=time_unix_nano (fixed64), 6=as_int (sfixed64)
    dp = (
        _pb_len(7, _pb_kv("outcome", outcome))
        + _pb_varint((2 << 3) | 1)
        + struct.pack("<Q", start_time_unix_nano)
        + _pb_varint((3 << 3) | 1)
        + struct.pack("<Q", time_unix_nano)
        + _pb_varint((6 << 3) | 1)
        + struct.pack("<q", value)
    )
    # Sum: 1=data_points, 2=aggregation_temporality (CUMULATIVE=2), 3=is_monotonic (true=1)
    sum_msg = (
        _pb_len(1, dp)
        + _pb_varint((2 << 3) | 0)
        + _pb_varint(2)
        + _pb_varint((3 << 3) | 0)
        + _pb_varint(1)
    )
    # Metric: 1=name, 3=unit, 7=sum
    metric = (
        _pb_str(1, "openmettle.runs.queue.slow_exits")
        + _pb_str(3, "{run}")
        + _pb_len(7, sum_msg)
    )
    # InstrumentationScope: 1=name, 2=version
    scope = _pb_str(1, "openmettle_core::telemetry") + _pb_str(2, "1.0.0")
    # ScopeMetrics: 1=scope, 2=metrics
    scope_metrics = _pb_len(1, scope) + _pb_len(2, metric)
    # Resource: 1=attributes
    resource = _pb_len(1, _pb_kv("service.name", service_name)) + _pb_len(
        1, _pb_kv("service.instance.id", instance_id)
    )
    # ResourceMetrics: 1=resource, 2=scope_metrics
    resource_metrics = _pb_len(1, resource) + _pb_len(2, scope_metrics)
    # ExportMetricsServiceRequest: 1=resource_metrics
    return _pb_len(1, resource_metrics)


def validate_delayed_baseline_samples(
    range_rows: list[dict], increase_rows: list[dict], relay_stats: dict
) -> dict:
    """Validate that a delayed startup 0 baseline followed by +1ms live 1 was stored in order."""
    if not range_rows:
        raise QualificationFailure("delayed startup baseline series missing from Prometheus")
    values = range_rows[0].get("values") or []
    if len(values) < 2:
        raise QualificationFailure(
            f"expected both [0, 1] samples for delayed startup baseline, got {values!r}"
        )
    parsed = [(float(ts), float(val)) for ts, val in values]
    if parsed[0][1] != 0.0 or parsed[-1][1] != 1.0:
        raise QualificationFailure(
            f"expected ordered [0.0, 1.0] samples after delayed baseline, got {parsed!r}"
        )
    if parsed[-1][0] <= parsed[0][0]:
        raise QualificationFailure(
            f"expected live sample timestamp > baseline timestamp, got {parsed!r}"
        )
    if not increase_rows:
        raise QualificationFailure(
            "increase(openmettle_runs_queue_slow_exits_total[10m]) returned no result"
        )
    increase_val = float(increase_rows[0]["value"][1])
    if increase_val < 1.0:
        raise QualificationFailure(
            f"expected increase(...) >= 1.0 for delayed startup baseline, got {increase_val}"
        )
    delayed = int(relay_stats.get("delayed", 0))
    status_4xx = int(relay_stats.get("status_4xx", 0))
    if delayed < 1:
        raise QualificationFailure(
            f"expected otlp-delay-relay to delay the baseline POST at least once, got {relay_stats!r}"
        )
    if status_4xx != 0:
        raise QualificationFailure(
            f"Prometheus returned {status_4xx} 4xx response(s) (out-of-order rejection): {relay_stats!r}"
        )
    return {
        "samples": len(parsed),
        "first_value": parsed[0][1],
        "last_value": parsed[-1][1],
        "increase_10m": increase_val,
        "relay_delayed": delayed,
        "relay_status_4xx": status_4xx,
    }


def https_post_otlp(
    port: int,
    path: str,
    body: bytes,
    *,
    ca_crt: str,
    server_hostname: str,
    timeout: float = 10.0,
) -> tuple[int | None, str]:
    """POST OTLP/HTTP protobuf over TLS to a port-forwarded collector verified against `ca_crt`."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_crt)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls_sock:
            tls_sock.settimeout(timeout)
            head = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {server_hostname}:{ALLOY_OTLP_PORT}\r\n"
                "Content-Type: application/x-protobuf\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(head + body)
            resp = http.client.HTTPResponse(tls_sock)
            resp.begin()
            payload = resp.read().decode("utf-8", errors="replace")
            return resp.status, payload
    except OSError as exc:
        return None, str(exc)


# --- Safety guards & HTTP/port-forward helpers -------------------------------------------

def check_cluster_absent(run, name: str) -> None:
    if not CLUSTER_NAME.fullmatch(name):
        raise Refusal("cluster name must be openmettle-dev-telemetry-<8 hex>")
    existing = run(["kind", "get", "clusters"]).stdout.split()
    if name in existing:
        raise Refusal(f"kind cluster {name} already exists; refusing to reuse it")


def check_openssl(run) -> None:
    try:
        result = run(["openssl", "version"], check=False, timeout=30)
    except Refusal as exc:
        raise Refusal("required runner tool missing: openssl") from exc
    if result.returncode != 0:
        raise Refusal("required runner tool unusable: openssl")


def http_request(
    port: int,
    path: str,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    *,
    method: str = "GET",
    data: bytes | None = None,
):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers=headers or {},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except OSError as exc:
        return None, str(exc)


class PortForward:
    def __init__(self, kubectl_args, env, namespace: str, target: str, port: int):
        self.proc = subprocess.Popen(
            [
                *kubectl_args,
                "--namespace", namespace,
                "port-forward", "--address", "127.0.0.1", target, f":{port}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        lines: queue.Queue = queue.Queue()

        def read():
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                lines.put(line)

        threading.Thread(target=read, daemon=True).start()
        deadline = time.monotonic() + 30
        while True:
            try:
                line = lines.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                self.close()
                raise QualificationFailure(f"port-forward to {namespace}/{target} did not start")
            match = re.match(r"Forwarding from 127\.0\.0\.1:(\d+) ->", line)
            if match:
                self.port = int(match.group(1))
                return

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --- Harness -----------------------------------------------------------------------------

def _log(message: str) -> None:
    print(f"[telemetry-qualify] {message}", file=sys.stderr, flush=True)


class TelemetryQualification:
    def __init__(
        self,
        process_contract: dict,
        telemetry_contract: dict,
        alerts_yaml: str,
        environ: dict,
        tools_dir: Path | None,
        workdir: Path,
    ):
        self.process_contract = process_contract
        self.telemetry_contract = telemetry_contract
        self.alerts_yaml = alerts_yaml
        self.context = check_opt_in(environ)
        self.run_id = secrets.token_hex(4)
        self.name = f"openmettle-dev-telemetry-{self.run_id}"
        self.workdir = workdir
        self.kubeconfig = workdir / "kubeconfig"
        self.env = child_environment(environ, self.kubeconfig, self.context, tools_dir)
        self.run = Runner(self.env)
        self.kubectl = [
            "kubectl", "--kubeconfig", str(self.kubeconfig),
            "--context", f"kind-{self.name}",
        ]
        self.images = {
            **{role: f"openmettle-{role}:telemetry-qual-{self.run_id}" for role in ROLES},
            "relay": f"openmettle-otlp-delay-relay:telemetry-qual-{self.run_id}",
        }
        self.ca_crt: str | None = None
        self.cluster_attempted = False
        self.built_images: list[str] = []
        self.report: dict = {
            "cluster": self.name,
            "classification": "dev",
            "kind": KIND_VERSION,
            "kubectl": KUBECTL_VERSION,
            "node_image": NODE_IMAGE,
            "prometheus_image": PROMETHEUS_IMAGE,
            "alloy_image": ALLOY_IMAGE,
            "checks": [],
        }

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
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(interval)
        raise QualificationFailure(f"timed out waiting for {description}")

    def pods(self, namespace: str, selector: str, include_terminating: bool = False) -> list[dict]:
        items = self.kube_json([
            "--namespace", namespace, "get", "pods", "--selector", selector, "--output=json",
        ])["items"]
        if include_terminating:
            return items
        return [p for p in items if not p["metadata"].get("deletionTimestamp")]

    def preflight(self):
        check_tools(self.run)
        check_openssl(self.run)
        check_docker_context(self.run, self.context)
        check_cluster_absent(self.run, self.name)
        if self.kubeconfig.exists():
            raise Refusal("temporary kubeconfig already exists")

    def verify_identity(self):
        config = json.loads(self.run([
            "kubectl", "--kubeconfig", str(self.kubeconfig), "config", "view", "--output=json",
        ]).stdout)
        nodes = [
            n["metadata"]["name"]
            for n in self.kube_json(["get", "nodes", "--output=json"])["items"]
        ]
        label = self.run([
            "docker", "inspect", "--format",
            '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}',
            f"{self.name}-control-plane",
        ]).stdout.strip()
        check_cluster_identity(config, nodes, label, self.name)
        for ns in (APP_NAMESPACE, DB_NAMESPACE, TELEMETRY_NAMESPACE):
            found = self.kube("get", "namespace", ns, "--output=json", check=False)
            if found.returncode == 0:
                labels = json.loads(found.stdout)["metadata"].get("labels", {})
                if labels.get("openmettle.dev/qualification-run") != self.run_id:
                    raise Refusal(f"namespace {ns} was not created by this run")

    def build_images(self):
        for role in ROLES:
            _log(f"building {self.images[role]} (local only; never pushed)")
            self.built_images.append(self.images[role])
            self.run([
                "docker", "build", "--builder", "default",
                "--target", self.process_contract[role]["imageTarget"],
                "--tag", self.images[role],
                str(ROOT),
            ], timeout=1800)
        _log(f"building {self.images['relay']} (test-only OTLP delay relay; never pushed)")
        self.built_images.append(self.images["relay"])
        self.run([
            "docker", "build", "--builder", "default",
            "--file", str(ROOT / "tests" / "telemetry_kind" / "Dockerfile.relay"),
            "--tag", self.images["relay"],
            str(ROOT / "tests" / "telemetry_kind"),
        ], timeout=600)

    def create_cluster(self):
        _log(f"creating kind cluster {self.name} (dev, temporary kubeconfig)")
        self.cluster_attempted = True
        self.run([
            "kind", "create", "cluster", "--name", self.name,
            "--image", NODE_IMAGE,
            "--kubeconfig", str(self.kubeconfig),
            "--wait", "180s",
        ], timeout=900)
        self.verify_identity()
        self.passed("isolated cluster identity", context=f"kind-{self.name}")
        for key in (*ROLES, "relay"):
            self.run(["kind", "load", "docker-image", self.images[key], "--name", self.name],
                     timeout=600)

    def deploy(self):
        passwords = {k: secrets.token_hex(16) for k in ("admin", *ROLES)}
        tls = generate_collector_tls(self.workdir)
        self.ca_crt = tls["ca_crt"]
        manifests = render_manifests(
            self.process_contract, self.images, passwords, tls, self.alerts_yaml, self.run_id,
        )
        # Apply namespaces, Postgres, Prometheus, relay, and Alloy first so the collector is ready
        # before openmettle-api/worker/gateway start and emit their initial zero-baseline drop series.
        infra_items = []
        app_items = []
        for item in manifests["items"]:
            if item["kind"] == "Deployment" and item["metadata"].get("namespace") == APP_NAMESPACE:
                app_items.append(item)
            else:
                infra_items.append(item)
        self.verify_identity()
        self.kube(
            "apply", "--filename", "-",
            input=json.dumps({"apiVersion": "v1", "kind": "List", "items": infra_items}),
        )
        self.kube("--namespace", DB_NAMESPACE, "rollout", "status", "deployment/postgres",
                  "--timeout=300s", timeout=330)
        self.kube("--namespace", TELEMETRY_NAMESPACE, "rollout", "status", "deployment/prometheus",
                  "--timeout=300s", timeout=330)
        self.kube("--namespace", TELEMETRY_NAMESPACE, "rollout", "status",
                  "deployment/otlp-delay-relay", "--timeout=180s", timeout=210)
        self.kube("--namespace", TELEMETRY_NAMESPACE, "rollout", "status", "deployment/alloy",
                  "--timeout=300s", timeout=330)
        self.verify_identity()
        self.kube(
            "apply", "--filename", "-",
            input=json.dumps({"apiVersion": "v1", "kind": "List", "items": app_items}),
        )
        for role in ROLES:
            self.kube("--namespace", APP_NAMESPACE, "rollout", "status",
                      f"deployment/openmettle-{role}", "--timeout=180s", timeout=210)
        self.passed("telemetry stack and app pods ready under restricted PSS")

    def prom_query(
        self, prom_port: int, expr: str, *, allow_transient: bool = False,
    ) -> list[dict] | None:
        encoded = urllib.parse.urlencode({"query": expr})
        status, body = http_request(prom_port, f"/api/v1/query?{encoded}")
        if status != 200:
            if allow_transient:
                return None
            raise QualificationFailure(
                f"Prometheus query {expr!r} failed: status={status} body={body[:300]}"
            )
        try:
            payload = json.loads(body)
        except ValueError as exc:
            if allow_transient:
                return None
            raise QualificationFailure(f"Prometheus query {expr!r} returned invalid JSON: {exc}") from exc
        if payload.get("status") != "success":
            if allow_transient:
                return None
            raise QualificationFailure(f"Prometheus query error: {payload}")
        return payload["data"]["result"]

    def prom_rules(self, prom_port: int, *, allow_transient: bool = False) -> list[dict] | None:
        status, body = http_request(prom_port, "/api/v1/rules")
        if status != 200:
            if allow_transient:
                return None
            raise QualificationFailure(f"Prometheus /api/v1/rules failed: status={status}")
        try:
            payload = json.loads(body)
        except ValueError as exc:
            if allow_transient:
                return None
            raise QualificationFailure(f"Prometheus /api/v1/rules returned invalid JSON: {exc}") from exc
        if payload.get("status") != "success":
            if allow_transient:
                return None
            raise QualificationFailure(f"Prometheus /api/v1/rules error: {payload}")
        return payload["data"]["groups"]

    def scale_alloy(self, replicas: int):
        self.verify_identity()
        self.kube("--namespace", TELEMETRY_NAMESPACE, "scale", "deployment/alloy",
                  f"--replicas={replicas}")
        if replicas == 0:
            self.wait_for(
                "alloy pods to terminate",
                lambda: not self.pods(TELEMETRY_NAMESPACE, "app.kubernetes.io/name=alloy",
                                      include_terminating=True),
                timeout=90,
            )
        else:
            self.kube("--namespace", TELEMETRY_NAMESPACE, "rollout", "status",
                      "deployment/alloy", "--timeout=180s", timeout=210)

    def scale_down_observing_exit(self, role: str) -> dict[str, int]:
        pods = self.pods(APP_NAMESPACE, f"app.kubernetes.io/name=openmettle-{role}")
        names = [p["metadata"]["name"] for p in pods]
        patch = json.dumps([{"op": "add", "path": "/metadata/finalizers", "value": [FINALIZER]}])
        for name in names:
            self.kube("--namespace", APP_NAMESPACE, "patch", "pod", name, "--type=json",
                      f"--patch={patch}")
        self.verify_identity()
        self.kube("--namespace", APP_NAMESPACE, "scale", f"deployment/openmettle-{role}",
                  "--replicas=0")
        exits: dict[str, int] = {}
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
        self.wait_for(
            f"{role} pods to be removed",
            lambda: not self.pods(APP_NAMESPACE, f"app.kubernetes.io/name=openmettle-{role}",
                                  include_terminating=True),
            timeout=60,
        )
        return exits

    def scenario(self):
        api_spec = self.process_contract["api"]
        gateway_spec = self.process_contract["gateway"]
        api_pods = self.pods(APP_NAMESPACE, "app.kubernetes.io/name=openmettle-api")
        self.expect(len(api_pods) == 1, f"expected 1 api pod, found {len(api_pods)}")
        api_pod = api_pods[0]["metadata"]["name"]
        gateway_pods = self.pods(APP_NAMESPACE, "app.kubernetes.io/name=openmettle-gateway")
        self.expect(len(gateway_pods) == 1, f"expected 1 gateway pod, found {len(gateway_pods)}")
        gateway_pod = gateway_pods[0]["metadata"]["name"]

        with contextlib.ExitStack() as stack:
            prom_pf = stack.enter_context(PortForward(
                self.kubectl, self.env, TELEMETRY_NAMESPACE,
                "service/prometheus", PROMETHEUS_PORT,
            ))
            alloy_pf = stack.enter_context(PortForward(
                self.kubectl, self.env, TELEMETRY_NAMESPACE,
                "service/alloy", ALLOY_ADMIN_PORT,
            ))
            api_pf = stack.enter_context(PortForward(
                self.kubectl, self.env, APP_NAMESPACE,
                f"pod/{api_pod}", api_spec["port"],
            ))
            gateway_pf = stack.enter_context(PortForward(
                self.kubectl, self.env, APP_NAMESPACE,
                f"pod/{gateway_pod}", gateway_spec["port"],
            ))

            # 1. Verify all 5 v1 Prometheus alert rules are loaded and healthy.
            def rules_loaded():
                groups = self.prom_rules(prom_pf.port, allow_transient=True)
                if not groups:
                    return None
                for group in groups:
                    if group.get("name") == "openmettle-core-v1":
                        rules = {r["name"]: r for r in group.get("rules", [])}
                        if all(
                            name in rules and rules[name].get("health") == "ok"
                            for name in EXPECTED_ALERTS
                        ):
                            return rules
                return None

            loaded_rules = self.wait_for("Prometheus v1 alert rules to evaluate cleanly",
                                         rules_loaded, timeout=60)
            self.passed("Prometheus loaded all v1 alert rules",
                        rules=sorted(loaded_rules.keys()))

            # 2. Generate live HTTP traffic on API and gateway: probes + traced routes with
            # synthetic canary headers/query strings.
            self.expect(http_request(api_pf.port, "/healthz") == (200, "ok\n"),
                        "API /healthz failed")
            self.expect(http_request(api_pf.port, "/readyz") == (200, "ready\n"),
                        "API /readyz failed")
            self.expect(http_request(gateway_pf.port, "/healthz") == (200, "ok\n"),
                        "gateway /healthz failed")
            self.expect(http_request(gateway_pf.port, "/readyz") == (200, "ready\n"),
                        "gateway /readyz failed")
            for _ in range(3):
                status, _ = http_request(
                    api_pf.port,
                    f"/qualification-trace-probe?secret={CANARY_QUERY_SECRET}",
                    headers={
                        "traceparent": CANARY_TRACEPARENT,
                        "Authorization": f"Bearer {CANARY_BEARER_TOKEN}",
                    },
                )
                self.expect(status == 404, f"expected 404 for unmatched probe, got {status}")
            # Send an unauthenticated POST /v1/chat/completions to openmettle-gateway with a
            # non-32-byte bearer containing CANARY_BEARER_TOKEN so credential() fails closed
            # with 401 before touching PostgreSQL while exercising matched /v1 telemetry.
            for _ in range(3):
                status, _ = http_request(
                    gateway_pf.port,
                    f"/v1/chat/completions?secret={CANARY_QUERY_SECRET}",
                    headers={
                        "x-request-id": GATEWAY_PROBE_REQUEST_ID,
                        "traceparent": CANARY_TRACEPARENT,
                        "Authorization": f"Bearer {CANARY_BEARER_TOKEN}-invalid",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                    data=b"{}",
                )
                self.expect(status == 401, f"expected 401 for unauthenticated gateway probe, got {status}")

            # 3. Verify Alloy accepted OTLP trace spans over HTTPS from both API and gateway
            # and respected redaction / traceparent ignoring.
            def alloy_accepted_spans():
                status, body = http_request(alloy_pf.port, "/metrics")
                if status != 200:
                    return None
                count = parse_alloy_accepted_spans(body)
                return count if count >= 6.0 else None

            accepted_spans = self.wait_for(
                "Alloy to accept OTLP trace spans over HTTPS", alloy_accepted_spans, timeout=60
            )

            def alloy_trace_logs_ready():
                logs = self.kube("--namespace", TELEMETRY_NAMESPACE, "logs",
                                 "deployment/alloy", "--tail=1000").stdout
                if (
                    "http.server.request" in logs
                    and "unmatched" in logs
                    and "/v1/chat/completions" in logs
                    and "openmettle-gateway" in logs
                ):
                    return logs
                return None

            alloy_logs = self.wait_for(
                "Alloy debug exporter to log API and gateway http.server.request spans",
                alloy_trace_logs_ready,
                timeout=30,
            )
            for forbidden in (CANARY_TRACE_ID, CANARY_QUERY_SECRET, CANARY_BEARER_TOKEN):
                self.expect(forbidden not in alloy_logs,
                            f"forbidden canary leaked into Alloy trace logs: {forbidden}")
            self.passed("HTTPS OTLP trace ingestion and inbound traceparent/secret redaction",
                        accepted_spans=accepted_spans)

            # 4. Verify Prometheus ingested API, worker and gateway metrics (including
            # zero-initialized drop counters) with valid contract labels.
            def core_metrics_ingested():
                unmatched = self.prom_query(
                    prom_pf.port,
                    'openmettle_http_server_requests_total{job="openmettle-api",'
                    'openmettle_route_class="unmatched",http_response_status_class="4xx"}',
                    allow_transient=True,
                )
                readyz = self.prom_query(
                    prom_pf.port,
                    'openmettle_db_readiness_checks_total{job="openmettle-api",outcome="ok"}',
                    allow_transient=True,
                )
                duration = self.prom_query(
                    prom_pf.port,
                    'openmettle_http_server_request_duration_seconds_count{job="openmettle-api",'
                    'openmettle_route_class="unmatched",http_response_status_class="4xx"}',
                    allow_transient=True,
                )
                worker = self.prom_query(
                    prom_pf.port,
                    'openmettle_db_readiness_checks_total{job="openmettle-worker",outcome="ok"}',
                    allow_transient=True,
                )
                worker_drift_baseline = self.prom_query(
                    prom_pf.port,
                    'openmettle_storage_quota_drift_total{job="openmettle-worker"}',
                    allow_transient=True,
                )
                gateway_v1 = self.prom_query(
                    prom_pf.port,
                    'openmettle_http_server_requests_total{job="openmettle-gateway",'
                    'http_request_method="POST",openmettle_route_class="v1",'
                    'http_response_status_class="4xx"}',
                    allow_transient=True,
                )
                gateway_readyz = self.prom_query(
                    prom_pf.port,
                    'openmettle_db_readiness_checks_total{job="openmettle-gateway",outcome="ok"}',
                    allow_transient=True,
                )
                gateway_duration = self.prom_query(
                    prom_pf.port,
                    'openmettle_http_server_request_duration_seconds_count{job="openmettle-gateway",'
                    'openmettle_route_class="v1",http_response_status_class="4xx"}',
                    allow_transient=True,
                )
                drop_baseline = self.prom_query(
                    prom_pf.port,
                    'openmettle_telemetry_dropped_total{job="openmettle-api",'
                    'signal="metric_exports"}',
                    allow_transient=True,
                )
                gateway_drop_baseline = self.prom_query(
                    prom_pf.port,
                    'openmettle_telemetry_dropped_total{job="openmettle-gateway",'
                    'signal="metric_exports"}',
                    allow_transient=True,
                )
                if (
                    unmatched and readyz and duration and worker and worker_drift_baseline
                    and gateway_v1 and gateway_readyz and gateway_duration
                    and drop_baseline and gateway_drop_baseline
                ):
                    return {
                        "api_unmatched_4xx": float(unmatched[0]["value"][1]),
                        "api_db_ready_ok": float(readyz[0]["value"][1]),
                        "api_duration_count": float(duration[0]["value"][1]),
                        "worker_db_ready_ok": float(worker[0]["value"][1]),
                        "worker_drift_baseline_series": worker_drift_baseline,
                        "gateway_v1_4xx": float(gateway_v1[0]["value"][1]),
                        "gateway_db_ready_ok": float(gateway_readyz[0]["value"][1]),
                        "gateway_duration_count": float(gateway_duration[0]["value"][1]),
                        "api_drop_baseline": float(drop_baseline[0]["value"][1]),
                        "gateway_drop_baseline": float(gateway_drop_baseline[0]["value"][1]),
                    }
                return None

            ingested = self.wait_for(
                "Prometheus OTLP metric ingestion for API, worker and gateway",
                core_metrics_ingested,
                timeout=90,
            )
            worker_drift_series = ingested.pop("worker_drift_baseline_series")
            drift_by_instance = validate_worker_quota_drift_baseline(
                worker_drift_series, self.telemetry_contract
            )
            self.expect(
                ingested["api_drop_baseline"] == 0.0,
                f"expected zero-initialized API metric_exports drop baseline before outage, got {ingested['api_drop_baseline']}",
            )
            self.expect(
                ingested["gateway_drop_baseline"] == 0.0,
                f"expected zero-initialized gateway metric_exports drop baseline before outage, got {ingested['gateway_drop_baseline']}",
            )
            all_series = self.prom_query(prom_pf.port, '{__name__=~"openmettle_.*"}')
            validation = validate_prometheus_series(all_series, self.telemetry_contract)
            instances = {}
            for role in ROLES:
                job = f"openmettle-{role}"
                job_instances = validation["instances_by_job"].get(job, [])
                self.expect(
                    len(job_instances) == 1,
                    f"expected 1 instance for {job}, got {validation['instances_by_job']}",
                )
                instances[job] = job_instances[0]
            self.expect(
                set(drift_by_instance.keys()) == {instances["openmettle-worker"]},
                f"worker quota drift baseline instances {sorted(drift_by_instance.keys())} "
                f"did not match live worker instance {[instances['openmettle-worker']]}",
            )
            self.expect(
                len(set(instances.values())) == len(ROLES),
                f"processes shared a service.instance.id: {instances}",
            )
            self.passed(
                "Prometheus OTLP metrics ingestion and contract label conformance",
                worker_quota_drift_baseline_outcomes=len(
                    drift_by_instance[instances["openmettle-worker"]]
                ),
                **ingested,
                **validation,
            )

            # 4b. Verify Alloy `sending_queue { enabled = true, num_consumers = 1 }` serializes
            # downstream OTLP delivery to Prometheus when the startup 0 baseline POST is delayed
            # by 1.5s ahead of a +1ms cumulative 1 sample (preventing 400 out-of-order rejection).
            assert self.ca_crt is not None
            probe_instance = str(uuid.uuid4())
            with (
                PortForward(
                    self.kubectl, self.env, TELEMETRY_NAMESPACE,
                    "service/otlp-delay-relay", RELAY_PORT,
                ) as relay_pf,
                PortForward(
                    self.kubectl, self.env, TELEMETRY_NAMESPACE,
                    "service/alloy", ALLOY_OTLP_PORT,
                ) as alloy_otlp_pf,
            ):
                arm_status, arm_body = http_request(
                    relay_pf.port,
                    f"/arm-delay?ms={RELAY_DELAY_MS}&match={probe_instance}",
                    method="POST",
                    data=b"",
                )
                self.expect(
                    arm_status == 200,
                    f"failed to arm otlp-delay-relay: status={arm_status} body={arm_body!r}",
                )
                start_ns = time.time_ns()
                baseline_body = encode_otlp_slow_exit_counter(
                    probe_instance, "claimed", start_ns, start_ns, 0
                )
                live_body = encode_otlp_slow_exit_counter(
                    probe_instance, "claimed", start_ns, start_ns + 1_000_000, 1
                )
                st0, body0 = https_post_otlp(
                    alloy_otlp_pf.port,
                    "/v1/metrics",
                    baseline_body,
                    ca_crt=self.ca_crt,
                    server_hostname=ALLOY_HOST,
                )
                st1, body1 = https_post_otlp(
                    alloy_otlp_pf.port,
                    "/v1/metrics",
                    live_body,
                    ca_crt=self.ca_crt,
                    server_hostname=ALLOY_HOST,
                )
                self.expect(st0 == 200, f"Alloy rejected baseline POST: {st0} {body0!r}")
                self.expect(st1 == 200, f"Alloy rejected live POST: {st1} {body1!r}")

                range_expr = (
                    'openmettle_runs_queue_slow_exits_total{job="openmettle-worker",'
                    f'instance="{probe_instance}",outcome="claimed"}}[10m]'
                )
                increase_expr = f"increase({range_expr})"

                def delayed_samples_stored():
                    r_rows = self.prom_query(prom_pf.port, range_expr, allow_transient=True)
                    i_rows = self.prom_query(prom_pf.port, increase_expr, allow_transient=True)
                    if (
                        r_rows
                        and len(r_rows[0].get("values") or []) >= 2
                        and i_rows
                    ):
                        return (r_rows, i_rows)
                    return None

                range_rows, increase_rows = self.wait_for(
                    "delayed startup baseline [0, 1] samples to land in Prometheus in order",
                    delayed_samples_stored,
                    timeout=30,
                    interval=0.5,
                )
                stats_status, stats_body = http_request(relay_pf.port, "/stats")
                self.expect(
                    stats_status == 200,
                    f"otlp-delay-relay /stats failed: status={stats_status} body={stats_body!r}",
                )
                relay_stats = json.loads(stats_body)
                ordered = validate_delayed_baseline_samples(range_rows, increase_rows, relay_stats)
                after_probe_series = self.prom_query(prom_pf.port, '{__name__=~"openmettle_.*"}')
                validate_prometheus_series(after_probe_series, self.telemetry_contract)
                self.passed(
                    "serialized Alloy downstream delivery preserves delayed startup zero baseline",
                    probe_instance=probe_instance,
                    delay_ms=RELAY_DELAY_MS,
                    **ordered,
                )

            # 5. Single collector outage: verify API and gateway resilience and that
            # OpenMettleTelemetryDropsDetected transitions from zero baseline through pending
            # into firing (for: 5m over [15m] window).
            alloy_pf.close()
            probe_results: list[tuple] = []
            stop_probing = threading.Event()

            def probe_loop():
                while not stop_probing.is_set():
                    probe_results.append(("api.healthz", http_request(api_pf.port, "/healthz")))
                    probe_results.append(("api.readyz", http_request(api_pf.port, "/readyz")))
                    probe_results.append(("gateway.healthz", http_request(gateway_pf.port, "/healthz")))
                    probe_results.append(("gateway.readyz", http_request(gateway_pf.port, "/readyz")))
                    time.sleep(0.25)

            def api_metric_drop_events() -> list[dict]:
                logs = self.kube("--namespace", APP_NAMESPACE, "logs", api_pod).stdout
                events = []
                for line in logs.splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if (
                        entry.get("event") == "telemetry.dropped"
                        and isinstance(entry.get("dropped_metric_exports"), int)
                        and entry["dropped_metric_exports"] > 0
                    ):
                        events.append(entry)
                return events

            def drop_counter_at_least(minimum: float):
                rows = self.prom_query(
                    prom_pf.port,
                    'openmettle_telemetry_dropped_total{job="openmettle-api",'
                    'signal="metric_exports"}',
                    allow_transient=True,
                )
                if not rows:
                    return None
                val = float(rows[0]["value"][1])
                return val if val >= minimum else None

            prober = threading.Thread(target=probe_loop, daemon=True)
            prober.start()
            try:
                _log("collector outage: scaling Alloy to 0 until telemetry.dropped is logged")
                self.scale_alloy(0)
                self.wait_for(
                    "openmettle-api stderr telemetry.dropped during collector outage",
                    lambda: api_metric_drop_events() or None,
                    timeout=45,
                )
                _log("collector recovery: scaling Alloy back to 1")
                self.scale_alloy(1)
                drops_after_outage = self.wait_for(
                    "metric_exports drop counter >= 1 in Prometheus after single outage",
                    lambda: drop_counter_at_least(1.0),
                    timeout=90,
                )
            finally:
                stop_probing.set()
                prober.join(timeout=10)

            bad_probes = [
                p for p in probe_results
                if (p[0].endswith(".healthz") and p[1] != (200, "ok\n"))
                or (p[0].endswith(".readyz") and p[1] != (200, "ready\n"))
            ]
            for label, pf in (("API", api_pf), ("gateway", gateway_pf)):
                pf_exit = pf.proc.poll()
                if pf_exit is not None:
                    raise QualificationFailure(
                        f"{label} port-forward exited unexpectedly with code {pf_exit} during collector "
                        f"outage ({len(bad_probes)}/{len(probe_results)} failed probes; sample={bad_probes[:5]!r})"
                    )
            self.expect(
                len(probe_results) >= 20 and not bad_probes,
                f"API/gateway probes degraded during collector outage: {len(bad_probes)} failures of "
                f"{len(probe_results)}; sample={bad_probes[:5]!r}",
            )

            # Verify zero restarts across API, worker and gateway.
            for role in ROLES:
                restarts = [
                    c.get("restartCount", 0)
                    for p in self.pods(APP_NAMESPACE, f"app.kubernetes.io/name=openmettle-{role}")
                    for c in p["status"].get("containerStatuses", [])
                ]
                self.expect(restarts and all(r == 0 for r in restarts),
                            f"{role} restarted during collector outage: {restarts}")

            # Verify structured stderr logs contain gateway DEBUG request completion entries,
            # telemetry.dropped events and zero canary leaks.
            api_logs = self.kube("--namespace", APP_NAMESPACE, "logs", api_pod).stdout
            gateway_logs = self.kube("--namespace", APP_NAMESPACE, "logs", gateway_pod).stdout
            gateway_request_events = parse_gateway_request_logs(gateway_logs)
            self.expect(
                len(gateway_request_events) >= 3,
                "expected at least 3 DEBUG http.request.completed 401 entries in "
                f"openmettle-gateway stderr logs, found {len(gateway_request_events)}",
            )
            for role_name, pod_logs in (
                ("openmettle-api", api_logs),
                ("openmettle-gateway", gateway_logs),
            ):
                for forbidden in (CANARY_TRACE_ID, CANARY_QUERY_SECRET, CANARY_BEARER_TOKEN):
                    self.expect(forbidden not in pod_logs,
                                f"forbidden canary leaked into {role_name} stderr logs: {forbidden}")
            dropped_events = api_metric_drop_events()
            self.expect(len(dropped_events) >= 1,
                        "expected at least one telemetry.dropped stderr event from collector outage")

            # Verify Prometheus evaluates OpenMettleTelemetryDropsDetected all the way to firing.
            def drops_alert_firing():
                groups = self.prom_rules(prom_pf.port, allow_transient=True)
                if not groups:
                    return None
                for group in groups:
                    if group.get("name") != "openmettle-core-v1":
                        continue
                    for rule in group.get("rules", []):
                        if rule.get("name") != "OpenMettleTelemetryDropsDetected":
                            continue
                        for alert in rule.get("alerts", []):
                            labels = alert.get("labels", {})
                            if (
                                alert.get("state") == "firing"
                                and labels.get("signal") == "metric_exports"
                            ):
                                return alert
                return None

            _log(
                f"drop counter reached {drops_after_outage}; waiting for "
                "OpenMettleTelemetryDropsDetected to reach firing state (for: 5m)"
            )
            firing_alert = self.wait_for(
                "Prometheus OpenMettleTelemetryDropsDetected alert to fire",
                drops_alert_firing,
                timeout=480,
                interval=5.0,
            )
            alert_labels = firing_alert.get("labels", {})
            for key, expected in (
                ("severity", "warning"),
                ("service", "openmettle-core"),
                ("signal_contract", "v1"),
                ("signal", "metric_exports"),
            ):
                self.expect(
                    alert_labels.get(key) == expected,
                    f"alert label {key}={alert_labels.get(key)!r} != {expected!r}",
                )
            final_series = self.prom_query(prom_pf.port, '{__name__=~"openmettle_.*"}')
            validate_prometheus_series(final_series, self.telemetry_contract)

            self.passed(
                "collector-outage resilience and Prometheus alert firing",
                probes_total=len(probe_results),
                drop_counter_baseline=ingested["api_drop_baseline"],
                drop_counter_after_outage=drops_after_outage,
                stderr_dropped_events=len(dropped_events),
                gateway_debug_request_events=len(gateway_request_events),
                alert_state=firing_alert.get("state"),
                alert_labels=alert_labels,
            )

        # 6. Clean SIGTERM shutdown with active OTLP trace + metrics exporters.
        worker_exits = self.scale_down_observing_exit("worker")
        gateway_exits = self.scale_down_observing_exit("gateway")
        api_exits = self.scale_down_observing_exit("api")
        self.passed(
            "clean SIGTERM shutdown with OTLP exporters",
            worker=worker_exits,
            gateway=gateway_exits,
            api=api_exits,
        )
        self.report["result"] = "passed"

    def diagnostics(self):
        if not self.kubeconfig.exists():
            return
        for args in (
            ["get", "pods", "--all-namespaces", "--output=wide"],
            ["--namespace", APP_NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"],
            ["--namespace", TELEMETRY_NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"],
            ["--namespace", APP_NAMESPACE, "logs", "--selector", "app.kubernetes.io/name",
             "--all-containers", "--prefix", "--tail=100"],
            ["--namespace", TELEMETRY_NAMESPACE, "logs", "--selector", "app.kubernetes.io/name",
             "--all-containers", "--prefix", "--tail=100"],
        ):
            result = self.kube(*args, check=False, timeout=60)
            print(result.stdout[-6000:] + result.stderr[-2000:], file=sys.stderr)

    def cleanup(self):
        commands = []
        if self.cluster_attempted:
            _log(f"deleting kind cluster {self.name}")
            commands.append((
                ["kind", "delete", "cluster", "--name", self.name,
                 "--kubeconfig", str(self.kubeconfig)],
                300,
            ))
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
    parser.add_argument("--tools-dir", type=Path, help="directory from tests/kubernetes/install-tools.sh")
    parser.add_argument("--report", type=Path, help="write observed (non-secret) results as JSON")
    args = parser.parse_args(argv)
    try:
        process_contract = load_contract()
        telemetry_contract = load_telemetry_contract()
        alerts_yaml = load_alerts_text()
    except ContractError as exc:
        print(f"contract error: {exc}", file=sys.stderr)
        return 2
    workdir = Path(tempfile.mkdtemp(prefix="openmettle-telemetry-qual-"))
    try:
        qualification = TelemetryQualification(
            process_contract,
            telemetry_contract,
            alerts_yaml,
            dict(os.environ),
            args.tools_dir.resolve() if args.tools_dir else None,
            workdir,
        )
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
    except Exception as exc:
        qualification.report["result"] = "failed"
        qualification.report["error"] = f"{type(exc).__name__}: {exc}"
        print(f"qualification failed unexpectedly ({type(exc).__name__}): {exc}", file=sys.stderr)
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
            args.report.write_text(json.dumps(qualification.report, indent=2) + "\n", encoding="utf-8")
    return status


if __name__ == "__main__":
    sys.exit(main())
