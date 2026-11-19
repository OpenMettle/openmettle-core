"""Offline unit tests for the V1-04 Keycloak 26.8.2 qualification fixture."""
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest

import fixture


class RealmAndSettingsTests(unittest.TestCase):
    def test_realm_configures_public_pkce_s256_client_rfc9207_and_synthetic_users(self):
        passwords = {"approved": "pw-approved-synthetic", "invited": "pw-invited-synthetic"}
        doc = fixture.realm(passwords)
        self.assertEqual(doc["realm"], fixture.REALM)
        self.assertTrue(doc["enabled"])
        self.assertEqual(doc["sslRequired"], "all")
        self.assertFalse(doc["registrationAllowed"])

        self.assertEqual(len(doc["clients"]), 1)
        client = doc["clients"][0]
        self.assertEqual(client["clientId"], fixture.CLIENT_ID)
        self.assertEqual(client["protocol"], "openid-connect")
        self.assertTrue(client["publicClient"])
        self.assertTrue(client["standardFlowEnabled"])
        self.assertFalse(client["implicitFlowEnabled"])
        self.assertFalse(client["directAccessGrantsEnabled"])
        self.assertFalse(client["serviceAccountsEnabled"])
        self.assertFalse(client["consentRequired"])
        self.assertEqual(client["redirectUris"], [fixture.CALLBACK])
        self.assertEqual(client["webOrigins"], [])
        self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")
        self.assertEqual(client["attributes"]["exclude.issuer.from.auth.response"], "false")

        users = {u["username"]: u for u in doc["users"]}
        self.assertEqual(set(users), {"synthetic-approved", "synthetic-invited"})
        for name, account in fixture.ACCOUNTS.items():
            user = users[account["username"]]
            self.assertEqual(user["id"], account["subject"])
            self.assertTrue(user["enabled"])
            self.assertTrue(user["emailVerified"])
            self.assertEqual(user["credentials"], [{
                "type": "password",
                "value": passwords[name],
                "temporary": False,
            }])

    def test_private_address_accepts_only_canonical_rfc1918_ipv4(self):
        for good in ("10.0.0.2", "172.16.0.2", "172.31.255.254", "192.168.1.5"):
            with self.subTest(good=good):
                self.assertEqual(str(fixture.private_address(good)), good)
        for bad in (
            "127.0.0.1", "8.8.8.8", "169.254.169.254", "100.64.0.1",
            "0.0.0.0", "::1", "fd00::1", "172.16.0.2/32", " 172.16.0.2",
            "010.0.0.1", "keycloak.provider.test", "",
        ):
            with self.subTest(bad=bad), self.assertRaises(fixture.Failure) as raised:
                fixture.private_address(bad)
            self.assertEqual(str(raised.exception), "provider address is not a private IPv4 address")
            if bad:
                self.assertNotIn(bad, str(raised.exception))

    def test_settings_document_sets_explicit_bounded_uncacheable_reuse_and_bundle_trust(self):
        doc = fixture.settings(Path("/tmp/example-dir"), "172.18.0.2")
        self.assertEqual(doc["version"], 2)
        refresh = doc["provider_refresh"]
        self.assertGreaterEqual(refresh["uncacheable_reuse_seconds"], refresh["cooldown_seconds"])
        self.assertLessEqual(refresh["uncacheable_reuse_seconds"], 300)
        self.assertLessEqual(refresh["uncacheable_reuse_seconds"], refresh["freshness_seconds"])
        self.assertEqual(len(doc["providers"]), 1)
        provider = doc["providers"][0]
        self.assertEqual(provider["id"], fixture.PROVIDER_ID)
        self.assertEqual(provider["issuer"], fixture.ISSUER)
        self.assertEqual(provider["client_id"], fixture.CLIENT_ID)
        self.assertEqual(provider["callback"], fixture.CALLBACK)
        self.assertEqual(provider["private_cidrs"], ["172.18.0.2/32"])
        self.assertEqual(provider["trust"], {
            "roots": "bundle",
            "bundle_path": "/tmp/example-dir/provider-ca.pem",
        })
        self.assertEqual(doc["browser"]["provider_id"], fixture.PROVIDER_ID)
        self.assertEqual(doc["browser"]["origin"], fixture.APPLICATION_ORIGIN)


class PrepareAndSettingsFilesystemTests(unittest.TestCase):
    def test_prepare_and_settings_create_expected_layout_permissions_and_silent_secrets(self):
        with tempfile.TemporaryDirectory(prefix="om-kc-test-") as parent:
            target = Path(parent) / "fixture"
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = fixture.main(["prepare", "--directory", str(target)])
            self.assertEqual(code, 0)
            self.assertEqual(stderr.getvalue(), "")

            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((target / "provider").stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((target / "import").stat().st_mode), 0o755)
            self.assertFalse((target / "work").exists())

            for rel, mode in (
                ("provider/tls-certificate.pem", 0o644),
                ("provider/tls-key.pem", 0o644),
                ("import/realm.json", 0o644),
                ("accounts.json", 0o600),
                ("login-key.bin", 0o600),
            ):
                path = target / rel
                self.assertTrue(path.is_file(), rel)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode, rel)

            self.assertEqual(len((target / "login-key.bin").read_bytes()), 32)
            accounts = json.loads((target / "accounts.json").read_text())
            self.assertEqual(set(accounts), {"approved", "invited"})
            passwords = [accounts[name]["password"] for name in ("approved", "invited")]
            self.assertEqual(len(set(passwords)), 2)
            for password in passwords:
                self.assertGreaterEqual(len(password), 24)
                self.assertNotIn(password, stdout.getvalue())
                self.assertNotIn(password, stderr.getvalue())

            # Leaf certificate verifies strictly against the per-run CA and carries the DNS SAN.
            verify = subprocess.run(
                ["openssl", "verify", "-CAfile", str(target / "provider-ca.pem"),
                 str(target / "provider/tls-certificate.pem")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            text = subprocess.run(
                ["openssl", "x509", "-in", str(target / "provider/tls-certificate.pem"), "-noout", "-text"],
                capture_output=True, text=True, check=True,
            ).stdout
            self.assertIn(f"DNS:{fixture.PROVIDER_HOST}", text)

            # `settings` writes auth-settings.json once and refuses to overwrite it.
            out2, err2 = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out2), contextlib.redirect_stderr(err2):
                code2 = fixture.main(["settings", "--directory", str(target), "--address", "172.18.0.2"])
            self.assertEqual(code2, 0)
            self.assertEqual(err2.getvalue(), "")
            settings_path = target / "auth-settings.json"
            self.assertEqual(stat.S_IMODE(settings_path.stat().st_mode), 0o600)
            parsed = json.loads(settings_path.read_text())
            self.assertEqual(parsed["providers"][0]["private_cidrs"], ["172.18.0.2/32"])

            err3 = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err3):
                code3 = fixture.main(["settings", "--directory", str(target), "--address", "172.18.0.2"])
            self.assertEqual(code3, 1)
            self.assertIn("auth settings document already exists", err3.getvalue())

    def test_prepare_refuses_existing_directory_and_settings_refuses_unprepared_directory(self):
        with tempfile.TemporaryDirectory(prefix="om-kc-err-") as parent, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(fixture.Failure, "^fixture directory must be new"):
                fixture.prepare(Path(parent))
            with self.assertRaisesRegex(fixture.Failure, "^fixture directory is not prepared$"):
                fixture.write_settings(Path(parent), "172.18.0.2")


class DiscoveryTlsAndWaitTests(unittest.TestCase):
    def _serve_once(self, cert, key, status, payload):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        return server, thread

    def test_discovery_verifies_tls_against_test_ca_and_checks_realm_endpoints(self):
        with tempfile.TemporaryDirectory(prefix="om-kc-tls-") as parent:
            good_dir = Path(parent) / "good"
            other_dir = Path(parent) / "other"
            with contextlib.redirect_stdout(io.StringIO()):
                fixture.prepare(good_dir)
                fixture.prepare(other_dir)

            expected = {"issuer": fixture.ISSUER, **fixture.ENDPOINTS}

            # Matching cert + matching discovery -> served
            server, thread = self._serve_once(
                good_dir / "provider/tls-certificate.pem",
                good_dir / "provider/tls-key.pem",
                200, expected,
            )
            port = server.server_address[1]
            outcome = fixture.discovery(
                good_dir / "provider-ca.pem",
                connect=lambda _addr, timeout: socket.create_connection(("127.0.0.1", port), timeout),
            )
            thread.join(timeout=5)
            server.server_close()
            self.assertEqual(outcome, "served")

            # Cert signed by another CA -> certificate refused
            server, thread = self._serve_once(
                other_dir / "provider/tls-certificate.pem",
                other_dir / "provider/tls-key.pem",
                200, expected,
            )
            port = server.server_address[1]
            outcome = fixture.discovery(
                good_dir / "provider-ca.pem",
                connect=lambda _addr, timeout: socket.create_connection(("127.0.0.1", port), timeout),
            )
            thread.join(timeout=5)
            server.server_close()
            self.assertEqual(outcome, "certificate refused")

            # Valid TLS, wrong realm -> other realm
            wrong = {**expected, "issuer": "https://keycloak.provider.test:8443/realms/wrong"}
            server, thread = self._serve_once(
                good_dir / "provider/tls-certificate.pem",
                good_dir / "provider/tls-key.pem",
                200, wrong,
            )
            port = server.server_address[1]
            outcome = fixture.discovery(
                good_dir / "provider-ca.pem",
                connect=lambda _addr, timeout: socket.create_connection(("127.0.0.1", port), timeout),
            )
            thread.join(timeout=5)
            server.server_close()
            self.assertEqual(outcome, "other realm")

    def test_wait_fails_immediately_on_certificate_or_realm_mismatch_and_retries_transient_states(self):
        sleeps = []
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(fixture.Failure, "provider certificate was not accepted"):
                fixture.wait(Path("/tmp/unused"), 30, probe=lambda _: "certificate refused", sleep=sleeps.append)
            self.assertEqual(sleeps, [])

            with self.assertRaisesRegex(fixture.Failure, "does not describe the fixture realm"):
                fixture.wait(Path("/tmp/unused"), 30, probe=lambda _: "other realm", sleep=sleeps.append)
            self.assertEqual(sleeps, [])

            replies = iter(["no connection", "not served", "served"])
            fixture.wait(Path("/tmp/unused"), 30, probe=lambda _: next(replies), sleep=sleeps.append)
            self.assertEqual(sleeps, [2, 2])


if __name__ == "__main__":
    unittest.main()
