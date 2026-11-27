"""Cluster-free tests for the V1-29 telemetry kind qualification harness and alert fixtures.

These cover safety guards, contract loading, synthetic CA/certificate generation, manifest
derivation, Prometheus series contract validation, and Alloy metric parsing. Passing them is
not qualification; the live evidence is the promtool + kind run in
.github/workflows/telemetry-qualification.yml.
"""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qualify  # noqa: E402

NAME = "openmettle-dev-telemetry-0123abcd"
OPTED_IN = {qualify.OPT_IN_VAR: qualify.OPT_IN_VALUE, qualify.DOCKER_CONTEXT_VAR: "default"}


def done(stdout="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, "")


class FakeRunner:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, args, **_):
        self.calls.append(args)
        for prefix, result in self.responses.items():
            if tuple(args[:len(prefix)]) == prefix:
                return result
        raise AssertionError(f"unexpected command {args}")


class ContractAndAlertsTests(unittest.TestCase):
    def test_loads_repository_telemetry_contract_and_alerts(self):
        contract = qualify.load_telemetry_contract()
        self.assertEqual(contract["contract_version"], "1.0.0")
        self.assertEqual(contract["policy"]["prometheus_translation"], "UnderscoreEscapingWithSuffixes")
        alerts_text = qualify.load_alerts_text()
        for name in qualify.EXPECTED_ALERTS:
            self.assertIn(f"alert: {name}", alerts_text)

    def test_promtool_test_file_covers_every_v1_alert_positive_and_negative(self):
        test_file = qualify.ROOT / "contracts" / "telemetry" / "alerts-v1-test.yaml"
        self.assertTrue(test_file.is_file())
        text = test_file.read_text(encoding="utf-8")
        self.assertIn("alerts-v1.yaml", text)
        for name in qualify.EXPECTED_ALERTS:
            self.assertGreaterEqual(
                text.count(f"alertname: {name}"),
                2,
                f"expected both positive and negative promtool tests for {name}",
            )


class SyntheticTlsTests(unittest.TestCase):
    def test_generates_valid_ephemeral_ca_and_collector_cert_and_cleans_ca_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            tls = qualify.generate_collector_tls(workdir)
            self.assertIn("BEGIN CERTIFICATE", tls["ca_crt"])
            self.assertIn("BEGIN CERTIFICATE", tls["tls_crt"])
            self.assertIn("BEGIN PRIVATE KEY", tls["tls_key"])
            self.assertFalse((workdir / "collector-tls").exists())

            # Verify the leaf cert chains to the CA and carries ALLOY_HOST in its SAN.
            ca_path = workdir / "ca.crt"
            srv_path = workdir / "tls.crt"
            ca_path.write_text(tls["ca_crt"], encoding="utf-8")
            srv_path.write_text(tls["tls_crt"], encoding="utf-8")
            verify = subprocess.run(
                ["openssl", "verify", "-CAfile", str(ca_path), str(srv_path)],
                capture_output=True, text=True, check=True,
            )
            self.assertIn(": OK", verify.stdout)
            text = subprocess.run(
                ["openssl", "x509", "-in", str(srv_path), "-noout", "-text"],
                capture_output=True, text=True, check=True,
            ).stdout
            self.assertIn(f"DNS:{qualify.ALLOY_HOST}", text)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.contract = qualify.load_contract()
        self.alerts_yaml = qualify.load_alerts_text()
        self.passwords = {"admin": "a" * 32, "api": "b" * 32, "worker": "c" * 32, "gateway": "d" * 32}
        self.tls = {"ca_crt": "FAKE-CA", "tls_crt": "FAKE-CERT", "tls_key": "FAKE-KEY"}
        images = {
            "api": "openmettle-api:telemetry-qual-x",
            "worker": "openmettle-worker:telemetry-qual-x",
            "gateway": "openmettle-gateway:telemetry-qual-x",
            "relay": "openmettle-otlp-delay-relay:telemetry-qual-x",
        }
        self.items = qualify.render_manifests(
            self.contract, images, self.passwords, self.tls, self.alerts_yaml, "0123abcd"
        )["items"]

    def find(self, kind, name):
        return next(i for i in self.items if i["kind"] == kind and i["metadata"]["name"] == name)

    def test_namespaces_labelled_dev_and_app_is_restricted(self):
        app_labels = self.find("Namespace", qualify.APP_NAMESPACE)["metadata"]["labels"]
        self.assertEqual(app_labels["pod-security.kubernetes.io/enforce"], "restricted")
        self.assertEqual(app_labels["openmettle.dev/environment"], "dev")
        self.assertEqual(app_labels["openmettle.dev/qualification-run"], "0123abcd")
        for ns in (qualify.DB_NAMESPACE, qualify.TELEMETRY_NAMESPACE):
            labels = self.find("Namespace", ns)["metadata"]["labels"]
            self.assertEqual(labels["openmettle.dev/environment"], "dev")
            self.assertEqual(labels["openmettle.dev/qualification-run"], "0123abcd")

    def test_api_worker_and_gateway_enable_https_otlp_with_ca_and_private_ranges(self):
        for role in qualify.ROLES:
            prefix = self.contract[role]["configurationPrefix"]
            pod = self.find("Deployment", f"openmettle-{role}")["spec"]["template"]["spec"]
            container = pod["containers"][0]
            env = {e["name"]: e.get("value") for e in container["env"]}
            self.assertTrue(all(k.startswith(prefix) for k in env))
            self.assertEqual(
                env[f"{prefix}OTLP_TRACES_ENDPOINT"],
                f"https://{qualify.ALLOY_HOST}:{qualify.ALLOY_OTLP_PORT}/v1/traces",
            )
            self.assertEqual(
                env[f"{prefix}OTLP_METRICS_ENDPOINT"],
                f"https://{qualify.ALLOY_HOST}:{qualify.ALLOY_OTLP_PORT}/v1/metrics",
            )
            self.assertEqual(env[f"{prefix}OTLP_CA_FILE"], qualify.OTLP_CA_FILE)
            self.assertEqual(env[f"{prefix}OTLP_PRIVATE_RANGES"], qualify.OTLP_PRIVATE_RANGES)
            if role == "gateway":
                self.assertEqual(env["OPENMETTLE_GATEWAY_UPSTREAM_URL"], "http://127.0.0.1:30000")
                self.assertEqual(env["OPENMETTLE_GATEWAY_MODEL"], "synthetic-model")
                self.assertEqual(env["OPENMETTLE_GATEWAY_LOG_LEVEL"], "debug")
            else:
                self.assertNotIn(f"{prefix}LOG_LEVEL", env)
            self.assertEqual(
                container["volumeMounts"],
                [{"name": "otlp-ca", "mountPath": qualify.OTLP_CA_MOUNT_DIR, "readOnly": True}],
            )
            self.assertIs(pod["automountServiceAccountToken"], False)
            self.assertIs(pod["enableServiceLinks"], False)
            self.assertIs(container["securityContext"]["readOnlyRootFilesystem"], True)

    def test_prometheus_and_alloy_use_pinned_digests_and_expected_flags(self):
        prom = self.find("Deployment", "prometheus")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(prom["image"], qualify.PROMETHEUS_IMAGE)
        self.assertIn("@sha256:", prom["image"])
        self.assertIn("--web.enable-otlp-receiver", prom["args"])
        prom_cfg = self.find("ConfigMap", "prometheus-config")["data"]["prometheus.yml"]
        self.assertIn("translation_strategy: UnderscoreEscapingWithSuffixes", prom_cfg)
        self.assertIn("/etc/prometheus/rules/alerts-v1.yaml", prom_cfg)
        self.assertEqual(
            self.find("ConfigMap", "prometheus-rules")["data"]["alerts-v1.yaml"],
            self.alerts_yaml,
        )

        alloy = self.find("Deployment", "alloy")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(alloy["image"], qualify.ALLOY_IMAGE)
        self.assertIn("@sha256:", alloy["image"])
        self.assertIn("--stability.level=experimental", alloy["args"])
        alloy_cfg = self.find("ConfigMap", "alloy-config")["data"]["config.alloy"]
        self.assertIn("cert_file", alloy_cfg)
        self.assertIn("insecure = true", alloy_cfg)
        self.assertIn(f"http://{qualify.RELAY_HOST}:{qualify.RELAY_PORT}/api/v1/otlp", alloy_cfg)
        self.assertIn('compression = "none"', alloy_cfg)
        self.assertIn("sending_queue {", alloy_cfg)
        self.assertRegex(alloy_cfg, r"enabled\s*=\s*true")
        self.assertRegex(alloy_cfg, r"num_consumers\s*=\s*1\b")

        relay_dep = self.find("Deployment", "otlp-delay-relay")
        self.assertEqual(relay_dep["metadata"]["namespace"], qualify.TELEMETRY_NAMESPACE)
        relay_pod = relay_dep["spec"]["template"]["spec"]
        self.assertIs(relay_pod["automountServiceAccountToken"], False)
        self.assertIs(relay_pod["enableServiceLinks"], False)
        self.assertIs(relay_pod["securityContext"]["runAsNonRoot"], True)
        relay_ctr = relay_pod["containers"][0]
        self.assertEqual(relay_ctr["image"], "openmettle-otlp-delay-relay:telemetry-qual-x")
        self.assertEqual(relay_ctr["imagePullPolicy"], "Never")
        self.assertIs(relay_ctr["securityContext"]["allowPrivilegeEscalation"], False)
        self.assertIs(relay_ctr["securityContext"]["readOnlyRootFilesystem"], True)
        self.assertEqual(relay_ctr["securityContext"]["capabilities"], {"drop": ["ALL"]})
        relay_svc = self.find("Service", "otlp-delay-relay")
        self.assertEqual(relay_svc["spec"]["ports"][0]["port"], qualify.RELAY_PORT)


class SeriesValidationAndParserTests(unittest.TestCase):
    def setUp(self):
        self.contract = qualify.load_telemetry_contract()
        self.uuid_api = "11111111-1111-4111-8111-111111111111"
        self.uuid_worker = "22222222-2222-4222-9222-222222222222"
        self.uuid_gateway = "33333333-3333-4333-8333-333333333333"

    def test_accepts_valid_contract_series(self):
        series = [
            {
                "metric": {
                    "__name__": "openmettle_http_server_requests_total",
                    "job": "openmettle-api",
                    "instance": self.uuid_api,
                    "http_request_method": "GET",
                    "openmettle_route_class": "unmatched",
                    "http_response_status_class": "4xx",
                },
                "value": [1, "3"],
            },
            {
                "metric": {
                    "__name__": "openmettle_db_readiness_duration_seconds_bucket",
                    "job": "openmettle-worker",
                    "instance": self.uuid_worker,
                    "outcome": "ok",
                    "le": "0.025",
                },
                "value": [1, "2"],
            },
            {
                "metric": {
                    "__name__": "openmettle_http_server_requests_total",
                    "job": "openmettle-gateway",
                    "instance": self.uuid_gateway,
                    "http_request_method": "POST",
                    "openmettle_route_class": "v1",
                    "http_response_status_class": "4xx",
                },
                "value": [1, "3"],
            },
            {
                "metric": {
                    "__name__": "openmettle_db_readiness_checks_total",
                    "job": "openmettle-gateway",
                    "instance": self.uuid_gateway,
                    "outcome": "ok",
                },
                "value": [1, "2"],
            },
            {
                "metric": {
                    "__name__": "openmettle_telemetry_dropped_total",
                    "job": "openmettle-api",
                    "instance": self.uuid_api,
                    "signal": "metric_exports",
                },
                "value": [1, "2"],
            },
        ]
        summary = qualify.validate_prometheus_series(series, self.contract)
        self.assertEqual(summary["series_count"], 5)
        self.assertEqual(summary["instances_by_job"]["openmettle-api"], [self.uuid_api])
        self.assertEqual(summary["instances_by_job"]["openmettle-worker"], [self.uuid_worker])
        self.assertEqual(summary["instances_by_job"]["openmettle-gateway"], [self.uuid_gateway])

    def test_rejects_unexpected_job_label(self):
        bad_job = [{
            "metric": {
                "__name__": "openmettle_db_readiness_checks_total",
                "job": "openmettle-unknown",
                "instance": self.uuid_gateway,
                "outcome": "ok",
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, "unexpected job label"):
            qualify.validate_prometheus_series(bad_job, self.contract)

    def test_cancellation_counter_allows_only_the_two_reasons(self):
        metric = {"__name__": "openmettle_runs_cancellations_total", "job": "openmettle-worker",
                  "instance": self.uuid_worker}
        for reason in ("requested", "revoked"):
            series = [{"metric": {**metric, "reason": reason}, "value": [1, "1"]}]
            self.assertEqual(qualify.validate_prometheus_series(series, self.contract)["series_count"], 1)
        series[0]["metric"]["reason"] = "unknown"
        with self.assertRaises(qualify.QualificationFailure):
            qualify.validate_prometheus_series(series, self.contract)

    def test_quota_drift_counter_allows_only_declared_outcomes(self):
        metric = {"__name__": "openmettle_storage_quota_drift_total", "job": "openmettle-worker",
                  "instance": self.uuid_worker}
        outcomes = (
            "healthy",
            "storage_accounts",
            "budgets",
            "settlements",
            "files",
            "quarantined",
            "error",
            "timeout",
        )
        for outcome in outcomes:
            series = [{"metric": {**metric, "outcome": outcome}, "value": [1, "1"]}]
            self.assertEqual(qualify.validate_prometheus_series(series, self.contract)["series_count"], 1)
        series[0]["metric"]["outcome"] = "unknown"
        with self.assertRaises(qualify.QualificationFailure):
            qualify.validate_prometheus_series(series, self.contract)

    def test_worker_quota_drift_baseline_requires_exact_eight_zero_outcomes(self):
        outcomes = (
            "healthy",
            "storage_accounts",
            "budgets",
            "settlements",
            "files",
            "quarantined",
            "error",
            "timeout",
        )
        baseline = [
            {
                "metric": {
                    "__name__": "openmettle_storage_quota_drift_total",
                    "job": "openmettle-worker",
                    "instance": self.uuid_worker,
                    "outcome": outcome,
                },
                "value": [1, "0"],
            }
            for outcome in outcomes
        ]
        validated = qualify.validate_worker_quota_drift_baseline(baseline, self.contract)
        self.assertEqual(set(validated.keys()), {self.uuid_worker})
        self.assertEqual(validated[self.uuid_worker], {o: 0.0 for o in outcomes})

        # Absent series must fail.
        with self.assertRaisesRegex(qualify.QualificationFailure, "missing openmettle_storage_quota_drift_total"):
            qualify.validate_worker_quota_drift_baseline([], self.contract)

        # Missing any single outcome must fail.
        with self.assertRaisesRegex(qualify.QualificationFailure, "missing=\\['timeout'\\]"):
            qualify.validate_worker_quota_drift_baseline(baseline[:-1], self.contract)

        # Non-zero baseline value must fail.
        nonzero = copy.deepcopy(baseline)
        nonzero[2]["value"] = [1, "1"]
        with self.assertRaisesRegex(qualify.QualificationFailure, "zero-initialized"):
            qualify.validate_worker_quota_drift_baseline(nonzero, self.contract)

        # Undeclared outcome must fail.
        undeclared = copy.deepcopy(baseline)
        undeclared[0]["metric"]["outcome"] = "unexpected"
        with self.assertRaisesRegex(qualify.QualificationFailure, "undeclared outcome"):
            qualify.validate_worker_quota_drift_baseline(undeclared, self.contract)

        # Unexpected extra label or non-worker job must fail.
        extra_label = copy.deepcopy(baseline)
        extra_label[0]["metric"]["extra"] = "bad"
        with self.assertRaisesRegex(qualify.QualificationFailure, "unexpected label"):
            qualify.validate_worker_quota_drift_baseline(extra_label, self.contract)

        wrong_job = copy.deepcopy(baseline)
        wrong_job[0]["metric"]["job"] = "openmettle-api"
        with self.assertRaisesRegex(qualify.QualificationFailure, "unexpected job"):
            qualify.validate_worker_quota_drift_baseline(wrong_job, self.contract)

    def test_rejects_disallowed_label_substring(self):
        bad = [{
            "metric": {
                "__name__": "openmettle_telemetry_dropped_total",
                "job": "openmettle-api",
                "instance": self.uuid_api,
                "signal": "metric_exports",
                "user_id": "u-123",
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, "disallowed label user_id"):
            qualify.validate_prometheus_series(bad, self.contract)

    def test_rejects_non_uuidv4_instance_and_out_of_enum_label(self):
        bad_instance = [{
            "metric": {
                "__name__": "openmettle_telemetry_dropped_total",
                "job": "openmettle-api",
                "instance": "pod-name-not-uuid",
                "signal": "metric_exports",
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, "non-UUIDv4"):
            qualify.validate_prometheus_series(bad_instance, self.contract)

        bad_enum = [{
            "metric": {
                "__name__": "openmettle_http_server_requests_total",
                "job": "openmettle-api",
                "instance": self.uuid_api,
                "http_request_method": "GET",
                "openmettle_route_class": "/raw/path/leak",
                "http_response_status_class": "4xx",
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, "outside contract enum"):
            qualify.validate_prometheus_series(bad_enum, self.contract)

    def test_rejects_undeclared_metric_label_le_and_missing_required_labels(self):
        undeclared_metric = [{
            "metric": {
                "__name__": "openmettle_undeclared_counter_total",
                "job": "openmettle-api",
                "instance": self.uuid_api,
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, "undeclared openmettle Prometheus series"):
            qualify.validate_prometheus_series(undeclared_metric, self.contract)

        undeclared_label = [{
            "metric": {
                "__name__": "openmettle_telemetry_dropped_total",
                "job": "openmettle-api",
                "instance": self.uuid_api,
                "signal": "metric_exports",
                "extra_tag": "unexpected",
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, "undeclared label extra_tag"):
            qualify.validate_prometheus_series(undeclared_label, self.contract)

        missing_label = [{
            "metric": {
                "__name__": "openmettle_db_readiness_checks_total",
                "job": "openmettle-api",
                "instance": self.uuid_api,
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, r"missing declared label\(s\): outcome"):
            qualify.validate_prometheus_series(missing_label, self.contract)

        missing_le = [{
            "metric": {
                "__name__": "openmettle_db_readiness_duration_seconds_bucket",
                "job": "openmettle-api",
                "instance": self.uuid_api,
                "outcome": "ok",
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, r"missing declared label\(s\): le"):
            qualify.validate_prometheus_series(missing_le, self.contract)

        undeclared_le = [{
            "metric": {
                "__name__": "openmettle_db_readiness_duration_seconds_bucket",
                "job": "openmettle-api",
                "instance": self.uuid_api,
                "outcome": "ok",
                "le": "999",
            }
        }]
        with self.assertRaisesRegex(qualify.QualificationFailure, "undeclared histogram bucket le=999"):
            qualify.validate_prometheus_series(undeclared_le, self.contract)

    def test_parses_alloy_accepted_spans_metric(self):
        sample = (
            "# HELP otelcol_receiver_accepted_spans_total Number of spans accepted.\n"
            'otelcol_receiver_accepted_spans_total{receiver="otelcol.receiver.otlp.default",transport="http"} 4\n'
            'otelcol_receiver_refused_spans_total{receiver="otelcol.receiver.otlp.default"} 0\n'
        )
        self.assertEqual(qualify.parse_alloy_accepted_spans(sample), 4.0)

    def test_parses_gateway_debug_request_logs(self):
        lines = [
            "not json",
            json.dumps({
                "level": "INFO",
                "event": "process.started",
                "role": "gateway",
            }),
            # Probe request at DEBUG must not count as /v1/chat/completions 401.
            json.dumps({
                "level": "DEBUG",
                "event": "http.request.completed",
                "request_id": "44444444-4444-4444-8444-444444444444",
                "http.route": "/readyz",
                "http.request.method": "GET",
                "http.response.status_code": 200,
                "duration_us": 120,
            }),
            # Echoing client x-request-id instead of generating a server UUID must not match.
            json.dumps({
                "level": "DEBUG",
                "event": "http.request.completed",
                "request_id": qualify.GATEWAY_PROBE_REQUEST_ID,
                "http.route": "/v1/chat/completions",
                "http.request.method": "POST",
                "http.response.status_code": 401,
                "duration_us": 250,
            }),
            # Boolean duration_us must not match as int.
            json.dumps({
                "level": "DEBUG",
                "event": "http.request.completed",
                "request_id": "55555555-5555-4555-8555-555555555555",
                "http.route": "/v1/chat/completions",
                "http.request.method": "POST",
                "http.response.status_code": 401,
                "duration_us": True,
            }),
            # Valid DEBUG 401 request completion entries.
            json.dumps({
                "level": "DEBUG",
                "event": "http.request.completed",
                "request_id": "66666666-6666-4666-8666-666666666666",
                "http.route": "/v1/chat/completions",
                "http.request.method": "POST",
                "http.response.status_code": 401,
                "duration_us": 310,
            }),
            json.dumps({
                "level": "DEBUG",
                "event": "http.request.completed",
                "request_id": "77777777-7777-4777-8777-777777777777",
                "http.route": "/v1/chat/completions",
                "http.request.method": "POST",
                "http.response.status_code": 401,
                "duration_us": 295,
            }),
        ]
        matched = qualify.parse_gateway_request_logs("\n".join(lines))
        self.assertEqual(
            [e["request_id"] for e in matched],
            [
                "66666666-6666-4666-8666-666666666666",
                "77777777-7777-4777-8777-777777777777",
            ],
        )

    def test_validate_delayed_baseline_samples_accepts_ordered_and_rejects_reordered(self):
        good_range = [{"values": [[1700000000.000, "0"], [1700000000.001, "1"]]}]
        good_inc = [{"value": [1700000005.0, "1"]}]
        good_stats = {"forwarded": 4, "delayed": 1, "armed_ms": 0, "status_4xx": 0}
        res = qualify.validate_delayed_baseline_samples(good_range, good_inc, good_stats)
        self.assertEqual(res["samples"], 2)
        self.assertEqual(res["first_value"], 0.0)
        self.assertEqual(res["last_value"], 1.0)
        self.assertEqual(res["increase_10m"], 1.0)
        self.assertEqual(res["relay_delayed"], 1)
        self.assertEqual(res["relay_status_4xx"], 0)

        # Single stored sample `[1]` (what happens when 0 is rejected out-of-order) must fail.
        with self.assertRaisesRegex(qualify.QualificationFailure, r"\[0, 1\]"):
            qualify.validate_delayed_baseline_samples(
                [{"values": [[1700000000.001, "1"]]}], good_inc, good_stats
            )

        # Equal timestamps must fail.
        with self.assertRaisesRegex(qualify.QualificationFailure, "timestamp"):
            qualify.validate_delayed_baseline_samples(
                [{"values": [[1700000000.0, "0"], [1700000000.0, "1"]]}], good_inc, good_stats
            )

        # Empty, non-finite (NaN/Inf), or <1 increase must fail.
        with self.assertRaisesRegex(qualify.QualificationFailure, "returned no result"):
            qualify.validate_delayed_baseline_samples(good_range, [], good_stats)
        for bad_inc in ("0", "NaN", "Inf", "+Inf", "-Inf"):
            with self.assertRaisesRegex(qualify.QualificationFailure, "increase"):
                qualify.validate_delayed_baseline_samples(
                    good_range, [{"value": [1700000005.0, bad_inc]}], good_stats
                )
        for bad_sample in ("NaN", "Inf"):
            with self.assertRaisesRegex(qualify.QualificationFailure, "non-finite"):
                qualify.validate_delayed_baseline_samples(
                    [{"values": [[1700000000.0, "0"], [1700000000.001, bad_sample]]}],
                    good_inc,
                    good_stats,
                )

        # Missing or non-integer (including boolean) relay_stats keys must fail.
        for bad_stats in (
            {"forwarded": 4, "delayed": 1, "armed_ms": 0},
            {"forwarded": 4, "armed_ms": 0, "status_4xx": 0},
            {**good_stats, "delayed": True},
            {**good_stats, "status_4xx": False},
        ):
            with self.assertRaisesRegex(qualify.QualificationFailure, "missing integer field"):
                qualify.validate_delayed_baseline_samples(good_range, good_inc, bad_stats)

        # Unfired delay or any 4xx rejection from Prometheus must fail.
        with self.assertRaisesRegex(qualify.QualificationFailure, "delay"):
            qualify.validate_delayed_baseline_samples(
                good_range, good_inc, {**good_stats, "delayed": 0}
            )
        with self.assertRaisesRegex(qualify.QualificationFailure, "4xx"):
            qualify.validate_delayed_baseline_samples(
                good_range, good_inc, {**good_stats, "status_4xx": 1}
            )

    def test_delay_relay_compiles_and_delays_only_matched_one_shot_post(self):
        import http.client
        import http.server
        import shutil
        import socket
        import threading
        import time

        if shutil.which("rustc") is None:
            self.skipTest("rustc not available in PATH")

        relay_src = Path(__file__).resolve().parent / "delay_relay.rs"
        received: list[tuple[str, bytes]] = []
        fail_next = [False]

        class UpstreamHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                received.append((self.path, body))
                status = 400 if fail_next[0] else 200
                fail_next[0] = False
                self.send_response(status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                return

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        up_port = upstream.server_address[1]
        up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        up_thread.start()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            relay_port = sock.getsockname()[1]

        proc = None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                binary = Path(tmp) / "otlp-delay-relay"
                subprocess.run(
                    [
                        "rustc", "--edition", "2024", "-D", "warnings",
                        str(relay_src), "-o", str(binary),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                proc = subprocess.Popen(
                    [str(binary)],
                    env={
                        "RELAY_BIND": f"127.0.0.1:{relay_port}",
                        "UPSTREAM_ADDR": f"127.0.0.1:{up_port}",
                    },
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    if qualify.http_request(relay_port, "/healthz") == (200, "ok\n"):
                        break
                    time.sleep(0.05)
                else:
                    self.fail("otlp-delay-relay did not become healthy")

                probe_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                other_id = "11111111-2222-4333-8444-555555555555"
                st, _ = qualify.http_request(
                    relay_port,
                    f"/arm-delay?ms=250&match={probe_id}",
                    method="POST",
                    data=b"",
                )
                self.assertEqual(st, 200)

                # Unrelated UUID must forward immediately without disarming the probe delay.
                other_body = qualify.encode_otlp_slow_exit_counter(
                    other_id, "claimed", 1_700_000_000_000_000_000, 1_700_000_000_000_000_000, 0
                )
                t0 = time.monotonic()
                st, _ = qualify.http_request(
                    relay_port, "/api/v1/otlp/v1/metrics", method="POST", data=other_body
                )
                self.assertEqual(st, 200)
                self.assertLess(time.monotonic() - t0, 0.2)

                # Matched baseline sent with Transfer-Encoding: chunked MUST trigger the 250ms delay.
                base_body = qualify.encode_otlp_slow_exit_counter(
                    probe_id, "claimed", 1_700_000_000_000_000_000, 1_700_000_000_000_000_000, 0
                )
                self.assertIn(probe_id.encode("ascii"), base_body)
                conn = http.client.HTTPConnection("127.0.0.1", relay_port, timeout=5)
                conn.putrequest("POST", "/api/v1/otlp/v1/metrics")
                conn.putheader("Content-Type", "application/x-protobuf")
                conn.putheader("Transfer-Encoding", "chunked")
                conn.endheaders()
                t0 = time.monotonic()
                conn.send(f"{len(base_body):x}\r\n".encode("ascii") + base_body + b"\r\n0\r\n\r\n")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                self.assertEqual(resp.status, 200)
                self.assertGreaterEqual(time.monotonic() - t0, 0.22)

                # Subsequent matched live snapshot must NOT be delayed (one-shot already disarmed).
                live_body = qualify.encode_otlp_slow_exit_counter(
                    probe_id, "claimed", 1_700_000_000_000_000_000, 1_700_000_000_001_000_000, 1
                )
                t0 = time.monotonic()
                st, _ = qualify.http_request(
                    relay_port, "/api/v1/otlp/v1/metrics", method="POST", data=live_body
                )
                self.assertEqual(st, 200)
                self.assertLess(time.monotonic() - t0, 0.2)

                # Upstream 400 must be reflected in status_4xx.
                fail_next[0] = True
                st, _ = qualify.http_request(
                    relay_port, "/api/v1/otlp/v1/metrics", method="POST", data=live_body
                )
                self.assertEqual(st, 400)

                st, stats_text = qualify.http_request(relay_port, "/stats")
                self.assertEqual(st, 200)
                stats = json.loads(stats_text)
                self.assertEqual(stats, {"forwarded": 4, "delayed": 1, "armed_ms": 0, "status_4xx": 1})
                self.assertEqual(received[0], ("/api/v1/otlp/v1/metrics", other_body))
                self.assertEqual(received[1], ("/api/v1/otlp/v1/metrics", base_body))
                self.assertEqual(received[2], ("/api/v1/otlp/v1/metrics", live_body))

                # Malformed chunked bodies (missing chunk CRLF, truncated trailer EOF, or LF-only
                # chunk size line) must return 400 Bad Request and never forward upstream.
                before_bad = len(received)
                for raw_bad in (
                    (
                        b"POST /api/v1/otlp/v1/metrics HTTP/1.1\r\n"
                        b"Host: relay\r\n"
                        b"Transfer-Encoding: chunked\r\n\r\n"
                        b"5\r\nhelloXX0\r\n\r\n"
                    ),
                    (
                        b"POST /api/v1/otlp/v1/metrics HTTP/1.1\r\n"
                        b"Host: relay\r\n"
                        b"Transfer-Encoding: chunked\r\n\r\n"
                        b"5\r\nhello\r\n0\r\n"
                    ),
                    (
                        b"POST /api/v1/otlp/v1/metrics HTTP/1.1\r\n"
                        b"Host: relay\r\n"
                        b"Transfer-Encoding: chunked\r\n\r\n"
                        b"5\nhello\r\n0\r\n\r\n"
                    ),
                ):
                    with socket.create_connection(("127.0.0.1", relay_port), timeout=5) as raw_sock:
                        raw_sock.sendall(raw_bad)
                        raw_sock.shutdown(socket.SHUT_WR)
                        reply = b""
                        while True:
                            chunk = raw_sock.recv(4096)
                            if not chunk:
                                break
                            reply += chunk
                    self.assertTrue(
                        reply.startswith(b"HTTP/1.1 400 Bad Request\r\n"),
                        f"expected 400 Bad Request for malformed chunked body {raw_bad!r}, got {reply!r}",
                    )
                self.assertEqual(len(received), before_bad)
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            upstream.shutdown()
            upstream.server_close()


class GuardTests(unittest.TestCase):
    def test_refuses_without_opt_in(self):
        with self.assertRaises(qualify.Refusal):
            qualify.check_opt_in({})

    def test_refuses_missing_openssl_during_preflight(self):
        runner = FakeRunner({("openssl", "version"): done(returncode=1)})
        with self.assertRaisesRegex(qualify.Refusal, "required runner tool unusable: openssl"):
            qualify.check_openssl(runner)

    def test_refuses_wrong_cluster_prefix_or_existing_cluster(self):
        runner = FakeRunner({("kind", "get", "clusters"): done(f"{NAME}\n")})
        with self.assertRaises(qualify.Refusal):
            qualify.check_cluster_absent(runner, "openmettle-dev-qual-0123abcd")
        with self.assertRaises(qualify.Refusal):
            qualify.check_cluster_absent(runner, NAME)

    def test_main_refuses_cleanly_without_creating_anything(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(qualify.main([]), 3)


if __name__ == "__main__":
    unittest.main()
