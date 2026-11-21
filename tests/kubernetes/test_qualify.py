"""Cluster-free tests for the Kubernetes qualification guards and contract-derived fixtures.

These cover refusal paths, manifests and recovery assertions. Passing them is not qualification;
the qualification evidence is the kind run in .github/workflows/kubernetes.yml.
"""
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qualify  # noqa: E402

NAME = "openmettle-dev-qual-0123abcd"
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


def kubeconfig(name=NAME, server="https://127.0.0.1:41234", extra_context=False):
    contexts = [{"name": f"kind-{name}"}] + ([{"name": "production"}] if extra_context else [])
    return {"current-context": f"kind-{name}", "contexts": contexts,
            "clusters": [{"name": f"kind-{name}", "cluster": {"server": server}}]}


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = qualify.load_contract()

    def test_repository_contract_is_valid(self):
        self.assertEqual(self.contract["api"]["serviceAccountName"], "openmettle-api")

    def test_rejects_shared_service_account(self):
        bad = copy.deepcopy(self.contract)
        bad["worker"]["serviceAccountName"] = bad["api"]["serviceAccountName"]
        with self.assertRaisesRegex(qualify.ContractError, "serviceAccountName"):
            qualify.validate_contract(bad)

    def test_rejects_token_automount(self):
        bad = copy.deepcopy(self.contract)
        bad["api"]["automountServiceAccountToken"] = True
        with self.assertRaisesRegex(qualify.ContractError, "automount"):
            qualify.validate_contract(bad)

    def test_rejects_missing_requests_and_wrong_prefix(self):
        bad = copy.deepcopy(self.contract)
        del bad["worker"]["requests"]["memory"]
        with self.assertRaisesRegex(qualify.ContractError, "requests"):
            qualify.validate_contract(bad)
        bad = copy.deepcopy(self.contract)
        bad["worker"]["configurationPrefix"] = "OPENMETTLE_API_"
        with self.assertRaises(qualify.ContractError):
            qualify.validate_contract(bad)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.contract = qualify.load_contract()
        self.passwords = {"admin": "a" * 32, "api": "b" * 32, "worker": "c" * 32}
        images = {"api": "openmettle-api:k8s-qual-x", "worker": "openmettle-worker:k8s-qual-x"}
        rendered = qualify.render_manifests(self.contract, images, self.passwords, "0123abcd")
        self.items = rendered["items"]

    def find(self, kind, name):
        return next(i for i in self.items if i["kind"] == kind and i["metadata"]["name"] == name)

    def test_deployments_follow_contract(self):
        for role in qualify.ROLES:
            spec = self.contract[role]
            pod = self.find("Deployment", f"openmettle-{role}")["spec"]["template"]["spec"]
            container = pod["containers"][0]
            self.assertEqual(pod["serviceAccountName"], spec["serviceAccountName"])
            self.assertIs(pod["automountServiceAccountToken"], False)
            self.assertIs(pod["enableServiceLinks"], False)
            self.assertEqual(container["resources"], {"requests": spec["requests"]})
            self.assertEqual(container["readinessProbe"]["httpGet"]["path"], spec["readinessPath"])
            self.assertEqual(container["livenessProbe"]["httpGet"]["path"], spec["livenessPath"])
            self.assertEqual(container["imagePullPolicy"], "Never")
            names = [e["name"] for e in container["env"]]
            self.assertTrue(all(n.startswith(spec["configurationPrefix"]) for n in names))
            self.assertNotIn("envFrom", container)
            account = self.find("ServiceAccount", spec["serviceAccountName"])
            self.assertIs(account["automountServiceAccountToken"], False)

    def test_only_worker_uses_fast_maintenance_sweeps(self):
        for role in qualify.ROLES:
            pod = self.find("Deployment", f"openmettle-{role}")["spec"]["template"]["spec"]
            env = {v["name"]: v.get("value") for v in pod["containers"][0]["env"]}
            self.assertEqual(env.get("OPENMETTLE_WORKER_SWEEP_MS"), "1000" if role == "worker" else None)
            self.assertNotIn("OPENMETTLE_WORKER_RUN_SLOTS", env)

    def test_processes_use_separate_credentials(self):
        for role in qualify.ROLES:
            url = self.find("Secret", f"openmettle-{role}-database")["stringData"]["url"]
            self.assertIn(f"openmettle_{role}:{self.passwords[role]}@", url)
        rendered = json.dumps(self.items)
        self.assertEqual(rendered.count(self.passwords["api"]), 2)  # URL and role SQL only

    def test_app_namespace_enforces_restricted_and_marks_dev(self):
        labels = self.find("Namespace", qualify.APP_NAMESPACE)["metadata"]["labels"]
        self.assertEqual(labels["pod-security.kubernetes.io/enforce"], "restricted")
        self.assertEqual(labels["openmettle.dev/environment"], "dev")
        self.assertEqual(labels["openmettle.dev/qualification-run"], "0123abcd")


class WorkerRecoveryTests(unittest.TestCase):
    def test_sigkill_targets_only_observed_worker_and_waits_for_a_new_ready_container(self):
        q = qualify.Qualification(qualify.load_contract(), OPTED_IN, None, Path("/tmp"))
        node = q.name + "-control-plane"
        old = "containerd://" + "a" * 64
        status = {"name": "worker", "ready": True, "restartCount": 0, "containerID": old}
        pod = {"metadata": {"name": "synthetic-worker"}, "spec": {"nodeName": node},
               "status": {"containerStatuses": [status]}}
        q.pods = Mock(return_value=[pod])
        q.verify_identity = Mock()
        q.exec = Mock(return_value="State:\tT (stopped)")
        q.run, q.seed_sweeps, q.assert_sweeps = Mock(), Mock(), Mock()
        new = {**status, "containerID": "containerd://" + "b" * 64, "restartCount": 1,
               "lastState": {"terminated": {"exitCode": 137}}}
        q.kube_json = Mock(side_effect=[
            {"status": {"containerStatuses": [sample]}} for sample in
            (status, {**new, "ready": False}, {**new, "lastState": {"terminated": {"exitCode": 0}}}, new)])
        with patch.object(qualify.time, "sleep"):
            q.forced_worker_recovery()
        cmd = ["docker", "exec", node, "ctr", "--namespace", "k8s.io", "tasks", "kill", "--signal"]
        self.assertEqual([call.args[0] for call in q.run.call_args_list],
                         [[*cmd, sig, "a" * 64] for sig in ("SIGSTOP", "SIGKILL")])
        self.assertEqual(q.kube_json.call_count, 4)
        q.seed_sweeps.assert_called_once_with("forced")
        q.assert_sweeps.assert_called_once_with("forced")
        pod["spec"]["nodeName"] = "foreign-node"
        with self.assertRaises(qualify.QualificationFailure):
            q.forced_worker_recovery()
        self.assertEqual(q.run.call_count, 2)

    def test_requires_both_terminal_events_and_payloads(self):
        q = qualify.Qualification(qualify.load_contract(), OPTED_IN, None, Path("/tmp"))
        queued = "graceful-queued|failed|openmettle.run-expired|{}"
        running = 'graceful-running|failed|openmettle.run-failed|{"reason":"deadline_exceeded"}'
        q.fixture_sql = Mock(side_effect=[queued, queued + "\n" + running.replace("failed", "cancelled"),
                                          queued + "\n" + running])
        with patch.object(qualify.time, "sleep"):
            q.assert_sweeps("graceful")
        self.assertEqual(q.fixture_sql.call_count, 3)


class GuardTests(unittest.TestCase):
    def test_requires_explicit_opt_in(self):
        for environ in ({}, {qualify.OPT_IN_VAR: "1"},
                        {qualify.OPT_IN_VAR: qualify.OPT_IN_VALUE}):
            with self.assertRaises(qualify.Refusal):
                qualify.check_opt_in(environ)
        self.assertEqual(qualify.check_opt_in(OPTED_IN), "default")

    def test_refuses_remote_or_conflicting_docker_selection(self):
        with self.assertRaisesRegex(qualify.Refusal, "DOCKER_HOST"):
            qualify.check_opt_in({**OPTED_IN, "DOCKER_HOST": "tcp://build:2376"})
        with self.assertRaisesRegex(qualify.Refusal, "DOCKER_CONTEXT"):
            qualify.check_opt_in({**OPTED_IN, "DOCKER_CONTEXT": "workstation"})
        for host in ("ssh://core@127.0.0.1:50634/run/podman.sock", "tcp://10.0.0.1:2376", ""):
            run = FakeRunner({("docker", "context", "inspect"): done(
                json.dumps([{"Endpoints": {"docker": {"Host": host}}}]))})
            with self.assertRaises(qualify.Refusal):
                qualify.check_docker_context(run, "default")
        run = FakeRunner({("docker", "context", "inspect"): done(
            json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]))})
        qualify.check_docker_context(run, "default")

    def test_child_environment_drops_inherited_targets(self):
        environ = {"KUBECONFIG": "/home/user/.kube/config", "DOCKER_HOST": "tcp://x",
                   "KIND_CLUSTER_NAME": "workstation", "KIND_EXPERIMENTAL_PROVIDER": "podman",
                   "BUILDX_BUILDER": "remote", "BUILDKIT_HOST": "tcp://remote:1234",
                   "BUILDX_CONFIG": "/tmp/foreign-builders",
                   "PATH": "/usr/bin"}
        env = qualify.child_environment(environ, Path("/tmp/q/kubeconfig"), "default",
                                        Path("/tmp/tools"))
        self.assertEqual(env["KUBECONFIG"], "/tmp/q/kubeconfig")
        self.assertEqual(env["DOCKER_CONTEXT"], "default")
        self.assertEqual(env["KIND_EXPERIMENTAL_PROVIDER"], "docker")
        self.assertNotIn("DOCKER_HOST", env)
        self.assertNotIn("KIND_CLUSTER_NAME", env)
        for key in ("BUILDX_BUILDER", "BUILDKIT_HOST", "BUILDX_CONFIG"):
            self.assertNotIn(key, env)
        self.assertTrue(env["PATH"].startswith("/tmp/tools"))

    def test_refuses_existing_cluster_and_unexpected_names(self):
        run = FakeRunner({("kind", "get", "clusters"): done(f"kind\n{NAME}\n")})
        with self.assertRaisesRegex(qualify.Refusal, "already exists"):
            qualify.check_cluster_absent(run, NAME)
        with self.assertRaisesRegex(qualify.Refusal, "cluster name"):
            qualify.check_cluster_absent(run, "kind")
        qualify.check_cluster_absent(FakeRunner({("kind", "get", "clusters"): done("kind\n")}), NAME)

    def test_refuses_unpinned_tools(self):
        kubectl = done(json.dumps({"clientVersion": {"gitVersion": qualify.KUBECTL_VERSION}}))
        run = FakeRunner({("kind", "version"): done("kind v0.29.0 go1.24 linux/amd64"),
                          ("kubectl", "version"): kubectl})
        with self.assertRaisesRegex(qualify.Refusal, "kind"):
            qualify.check_tools(run)
        run = FakeRunner({("kind", "version"): done(f"kind {qualify.KIND_VERSION} go linux/amd64"),
                          ("kubectl", "version"): done('{"clientVersion":{"gitVersion":"v1.30.0"}}')})
        with self.assertRaisesRegex(qualify.Refusal, "kubectl"):
            qualify.check_tools(run)

    def test_cluster_identity(self):
        node = [f"{NAME}-control-plane"]
        qualify.check_cluster_identity(kubeconfig(), node, NAME, NAME)
        cases = [
            (kubeconfig(name="openmettle-dev-qual-ffffffff"), node, NAME),
            (kubeconfig(extra_context=True), node, NAME),
            (kubeconfig(server="https://10.0.0.5:6443"), node, NAME),
            (kubeconfig(), ["prod-node-1"], NAME),
            (kubeconfig(), node, "workstation"),
        ]
        for config, nodes, label in cases:
            with self.assertRaises(qualify.Refusal):
                qualify.check_cluster_identity(config, nodes, label, NAME)


class PortForwardTests(unittest.TestCase):
    def test_port_forward_targets_application_namespace(self):
        proc = Mock()
        proc.stdout = io.StringIO("Forwarding from 127.0.0.1:12345 -> 8080\n")
        proc.poll.return_value = 0
        args = ["kubectl", "--kubeconfig", "/tmp/fixture/config", "--context", "kind-fixture"]
        with patch.object(qualify.subprocess, "Popen", return_value=proc) as popen:
            forward = qualify.PortForward(args, {}, "pod/api-fixture", 8080)
            self.assertEqual(forward.port, 12345)
            command = popen.call_args.args[0]
            self.assertEqual(command[:len(args)], args)
            self.assertEqual(command[len(args):len(args) + 2], ["--namespace", qualify.APP_NAMESPACE])
            self.assertIn("pod/api-fixture", command)
            forward.close()


class CleanupTests(unittest.TestCase):
    def make(self):
        workdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(workdir, ignore_errors=True))
        q = qualify.Qualification(qualify.load_contract(), OPTED_IN, None, workdir)
        q.run = FakeRunner({("kind", "delete"): done(), ("docker", "image", "rm"): done()})
        return q

    def test_constructor_refuses_without_opt_in(self):
        with self.assertRaises(qualify.Refusal):
            qualify.Qualification(qualify.load_contract(), {}, None, Path("/nonexistent"))

    def test_no_cluster_deletion_unless_this_run_created_it(self):
        q = self.make()
        q.cleanup()
        self.assertEqual(q.run.calls, [])

    def test_builds_use_validated_context_default_builder(self):
        q = self.make()
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[:3] == ["docker", "image", "inspect"]:
                role = "worker" if "worker" in args[-1] else "api"
                return done(json.dumps({"ExposedPorts": {f"{q.contract[role]['port']}/tcp": {}},
                                        "User": qualify.IMAGE_USER,
                                        "Entrypoint": [f"/usr/local/bin/openmettle-{role}"]}))
            return done()
        q.run = run
        q.build_images()
        builds = [c for c in calls if c[:2] == ["docker", "build"]]
        self.assertEqual(len(builds), 2)
        self.assertTrue(all(c[2:4] == ["--builder", "default"] for c in builds))

    def test_cleanup_attempts_remaining_resources_after_failure(self):
        q = self.make()
        q.cluster_attempted = True
        q.built_images = list(q.images.values())
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[0] == "kind":
                raise subprocess.TimeoutExpired(args, 300)
            return done(returncode=1)
        q.run = run
        failures = q.cleanup()
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(failures), 3)
        self.assertIn("TimeoutExpired", failures[0])

    def test_cleanup_failure_overrides_successful_scenario(self):
        q = self.make()
        q.report["result"] = "passed"
        report = q.kubeconfig.parent / "report.json"
        with patch.object(qualify, "Qualification", return_value=q), \
                patch.object(q, "preflight"), patch.object(q, "build_images"), \
                patch.object(q, "create_cluster"), patch.object(q, "deploy"), \
                patch.object(q, "scenario"), \
                patch.object(q, "cleanup", return_value=["kind delete: exit 1"]), \
                patch.object(qualify.tempfile, "mkdtemp", return_value=str(q.kubeconfig.parent)):
            self.assertEqual(qualify.main(["--report", str(report)]), 1)
        data = json.loads(report.read_text())
        self.assertEqual(data["result"], "failed")
        self.assertEqual(data["cleanup_errors"], ["kind delete: exit 1"])

    def test_cleanup_deletes_only_own_cluster_and_images(self):
        q = self.make()
        q.cluster_attempted = True
        q.built_images = [q.images["api"]]
        q.cleanup()
        self.assertEqual(q.run.calls[0], ["kind", "delete", "cluster", "--name", q.name,
                                          "--kubeconfig", str(q.kubeconfig)])
        self.assertEqual(q.run.calls[1], ["docker", "image", "rm", q.images["api"]])
        self.assertTrue(qualify.CLUSTER_NAME.fullmatch(q.name))
        self.assertTrue(q.images["api"].endswith(f":k8s-qual-{q.run_id}"))

    def test_kubectl_always_targets_temporary_kubeconfig(self):
        q = self.make()
        self.assertEqual(q.kubectl[:5], ["kubectl", "--kubeconfig", str(q.kubeconfig),
                                         "--context", f"kind-{q.name}"])


if __name__ == "__main__":
    unittest.main()
