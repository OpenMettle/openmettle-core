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
        self.assertIn("/api/v1/otlp", alloy_cfg)


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
