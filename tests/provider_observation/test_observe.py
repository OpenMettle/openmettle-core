"""Offline tests for the observer's transport, sanitization and verdicts. No provider runs here."""
import json
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import observe  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]

# Serves a canned response per request path, and records the exact request bytes received.
RELAY = r"""
import json, sys
request = sys.stdin.buffer.read()
spec = json.load(open(sys.argv[1]))
with open(sys.argv[2], "ab") as log:
    log.write(request + b"\x00")
path = request.split(b" ")[1].decode()
entry = spec.get(path)
if entry is None:
    sys.exit(97)
if entry.get("sleep"):
    import time; time.sleep(entry["sleep"])
sys.stdout.buffer.write(bytes.fromhex(entry["hex"]))
sys.stdout.buffer.flush()
"""

KEYCLOAK_LIKE_HEADERS = [
    ("Cache-Control", "no-cache, no-store"),
    ("Content-Type", "application/json"),
    ("Referrer-Policy", "no-referrer"),
]


def response(status=200, headers=(), body=b"", chunked=False):
    reason = {200: "OK", 302: "Found", 404: "Not Found"}.get(status, "X")
    lines = [f"HTTP/1.1 {status} {reason}"] + [f"{k}: {v}" for k, v in headers]
    if chunked:
        lines.append("Transfer-Encoding: chunked")
        payload = b"".join(b"%x\r\n%s\r\n" % (len(body[i:i + 7]), body[i:i + 7]) for i in range(0, len(body), 7))
        payload += b"0\r\n\r\n"
    else:
        lines.append(f"Content-Length: {len(body)}")
        payload = body
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + payload


def discovery(**overrides):
    document = {
        "issuer": observe.ISSUER,
        "authorization_endpoint": observe.AUTHORIZATION_URL,
        "token_endpoint": observe.TOKEN_URL,
        "jwks_uri": observe.ORIGIN + observe.JWKS_PATH,
        "response_types_supported": ["code", "none", "id_token"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "token_endpoint_auth_methods_supported": [
            "private_key_jwt", "client_secret_basic", "client_secret_post", "tls_client_auth", "client_secret_jwt",
        ],
        "code_challenge_methods_supported": ["plain", "S256"],
        "authorization_response_iss_parameter_supported": True,
    }
    document.update(overrides)
    return json.dumps(document).encode()


def jwks(*keys):
    keys = keys or ({"kid": "synthetic", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "AQAB", "e": "AQAB"},)
    return json.dumps({"keys": list(keys)}).encode()


class Relay:
    def __init__(self, routes):
        self.dir = tempfile.TemporaryDirectory()
        base = Path(self.dir.name)
        self.spec, self.log = base / "spec.json", base / "requests.bin"
        self.spec.write_text(json.dumps({p: {"hex": r.hex(), **({"sleep": s} if s else {})} for p, (r, s) in routes.items()}))
        self.argv = [sys.executable, "-I", "-c", RELAY, str(self.spec), str(self.log)]

    def requests(self):
        return [r for r in self.log.read_bytes().split(b"\x00") if r] if self.log.exists() else []

    def close(self):
        self.dir.cleanup()


def relay(discovery_response, jwks_response=None, sleep=0):
    routes = {observe.DISCOVERY_PATH: (discovery_response, sleep)}
    if jwks_response is not None:
        routes[observe.JWKS_PATH] = (jwks_response, 0)
    return Relay(routes)


class RequestTests(unittest.TestCase):
    def test_accept_matches_production_document_request(self):
        source = (ROOT / "src" / "provider_http.rs").read_text()
        found = re.findall(r"\.header\(header::ACCEPT, \"([^\"]+)\"\)", source)
        self.assertEqual(found, [observe.ACCEPT])

    def test_request_carries_host_accept_and_connection_close(self):
        self.assertEqual(
            observe.request_bytes(observe.JWKS_PATH),
            b"GET /realms/master/protocol/openid-connect/certs HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8080\r\nAccept: application/json, application/jwk-set+json\r\nConnection: close\r\n\r\n",
        )

    def test_document_paths_are_fixed_and_local(self):
        self.assertEqual(observe.ISSUER, "http://127.0.0.1:8080/realms/master")
        self.assertTrue(observe.DISCOVERY_PATH.startswith("/realms/master/"))
        self.assertTrue(observe.JWKS_PATH.startswith("/realms/master/"))


class ExchangeTests(unittest.TestCase):
    def run_one(self, raw, seconds=10, sleep=0):
        r = relay(raw, sleep=sleep)
        self.addCleanup(r.close)
        result = observe.exchange(r.argv, observe.DISCOVERY_PATH, seconds)
        self.assertEqual(r.requests(), [observe.request_bytes(observe.DISCOVERY_PATH)])
        return result

    def test_parses_length_and_chunked_bodies(self):
        for chunked in (False, True):
            status, headers, body = self.run_one(response(200, KEYCLOAK_LIKE_HEADERS, b'{"a": 1}', chunked))
            self.assertEqual((status, body), (200, b'{"a": 1}'))
            self.assertIn(("Cache-Control", "no-cache, no-store"), headers)

    def test_redirect_is_returned_not_followed(self):
        status, headers, _ = self.run_one(response(302, [("Location", "http://elsewhere.invalid/")]))
        self.assertEqual(status, 302)
        self.assertTrue(observe.header_facts(status, headers)["location_present"])

    def test_oversized_document_fails(self):
        with self.assertRaisesRegex(observe.Failure, "size limit"):
            self.run_one(response(200, KEYCLOAK_LIKE_HEADERS, b"x" * (observe.MAX_DOCUMENT_BYTES + 1)))

    def test_short_response_fails_even_when_body_is_valid_json(self):
        with self.assertRaisesRegex(observe.Failure, "no complete HTTP response"):
            self.run_one(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{}")

    def test_non_http_output_fails(self):
        with self.assertRaisesRegex(observe.Failure, "no complete HTTP response"):
            self.run_one(b"bash: connect: Connection refused\n")

    def test_hung_relay_is_killed(self):
        started = time.monotonic()
        with self.assertRaises(observe.Failure):
            self.run_one(response(200, KEYCLOAK_LIKE_HEADERS, b"{}"), seconds=1, sleep=30)
        self.assertLess(time.monotonic() - started, 15)


class FactTests(unittest.TestCase):
    def test_header_facts(self):
        facts = observe.header_facts(200, [
            ("Content-Type", "application/jwk-set+json; charset=UTF-8"),
            ("Date", "Wed, 18 Nov 2026 12:00:00 GMT"),
            ("Age", "7"),
            ("Cache-Control", 'max-age="60", no-cache="Set-Cookie"'),
            ("cache-control", "public, max-age=5"),
        ])
        self.assertEqual(facts["content_type"], {"count": 1, "media_type": "application/jwk-set+json",
                                                 "charset_utf8": True, "other_parameters": 0})
        self.assertEqual(facts["date"], {"count": 1, "imf_fixdate": True})
        self.assertEqual(facts["age"], {"count": 1, "value": 7})
        self.assertEqual(facts["cache_control"], {
            "count": 2, "directives": {"max-age": 5, "no-cache": "argument", "public": True},
            "repeated_directives": 1, "unknown_directives": 0,
        })

    def test_absent_date_age_and_cache_headers(self):
        facts = observe.header_facts(200, [("Content-Type", "text/html")])
        self.assertEqual(facts["date"], {"count": 0, "imf_fixdate": False})
        self.assertEqual(facts["age"], {"count": 0, "value": None})
        self.assertEqual(facts["cache_control"]["count"], 0)
        self.assertEqual(facts["content_type"]["media_type"], "other")

    def test_duplicate_members_are_rejected(self):
        with self.assertRaisesRegex(observe.Failure, "repeats a member"):
            observe.parse_document(b'{"issuer": "a", "nested": {"x": 1, "x": 2}}')


class ObserveTests(unittest.TestCase):
    def observe(self, discovery_response, jwks_response):
        r = relay(discovery_response, jwks_response)
        self.addCleanup(r.close)
        report = observe.observe(r.argv, 5)
        self.assertEqual(r.requests(), [observe.request_bytes(observe.DISCOVERY_PATH),
                                        observe.request_bytes(observe.JWKS_PATH)])
        return report

    def test_keycloak_headers_and_omitted_none_are_compatible_under_bounded_uncacheable_reuse(self):
        discovery_headers = [
            ("Cache-Control", "no-cache, no-store, must-revalidate, no-transform"),
            ("Content-Type", "application/json; charset=UTF-8"),
        ]
        jwks_headers = [
            ("Cache-Control", "no-cache"),
            ("Content-Type", "application/json"),
        ]
        report = self.observe(response(200, discovery_headers, discovery()),
                              response(200, jwks_headers, jwks()))
        outcome = report["outcome"]
        self.assertEqual(outcome["failures"], [])
        self.assertEqual(outcome["incompatibilities"], [])
        self.assertEqual(outcome["classification"], "compatible-with-bounded-uncacheable-reuse")
        self.assertEqual(outcome["bounded_reuse_notes"], [
            "discovery token_endpoint_auth_methods_supported omits none (accepted under ADR 0011 amendment)",
            "discovery Cache-Control refuses caching (requires bounded provider_refresh.uncacheable_reuse_seconds)",
            "jwks Cache-Control refuses caching (requires bounded provider_refresh.uncacheable_reuse_seconds)",
        ])
        self.assertFalse(outcome["login_attempted"])
        self.assertFalse(outcome["provider_support_claimed"])
        self.assertEqual(report["discovery"]["headers"]["cache_control"]["directives"], {
            "must-revalidate": True, "no-cache": True, "no-store": True, "no-transform": True,
        })
        self.assertEqual(report["jwks"]["headers"]["cache_control"]["directives"], {"no-cache": True})
        meta = report["discovery"]["metadata"]
        self.assertEqual(meta["code_challenge_methods_supported"], {"shape": "array", "known": ["S256", "plain"], "other": 0})
        self.assertIs(meta["authorization_response_iss_parameter_supported"], True)
        self.assertEqual(report["jwks"]["keys"]["rsa_rs256_signing_keys"], 1)

    def test_cacheable_provider_with_date_and_max_age_is_compatible(self):
        headers = [
            ("Content-Type", "application/json"),
            ("Date", "Wed, 18 Nov 2026 12:00:00 GMT"),
            ("Cache-Control", "max-age=300"),
        ]
        methods = ["client_secret_basic", "none"]
        report = self.observe(response(200, headers, discovery(token_endpoint_auth_methods_supported=methods)),
                              response(200, headers, jwks()))
        outcome = report["outcome"]
        self.assertEqual(outcome["failures"], [])
        self.assertEqual(outcome["incompatibilities"], [])
        self.assertEqual(outcome["bounded_reuse_notes"], [])
        self.assertEqual(outcome["classification"], "compatible")

    def test_max_age_without_date_is_incompatible(self):
        headers = [("Content-Type", "application/json"), ("Cache-Control", "max-age=300")]
        report = self.observe(response(200, headers, discovery()), response(200, headers, jwks()))
        self.assertEqual(report["outcome"]["classification"], "observed-incompatibility")
        self.assertIn("discovery freshness headers are incompatible", report["outcome"]["incompatibilities"])
        self.assertIn("jwks freshness headers are incompatible", report["outcome"]["incompatibilities"])

    def test_quoted_extension_value_cannot_count_as_a_cache_directive(self):
        headers = [("Content-Type", "application/json"), ("Cache-Control", 'extension="a, no-store, b"')]
        report = self.observe(response(200, headers, discovery()), response(200, headers, jwks()))
        self.assertEqual(report["outcome"]["classification"], "observed-incompatibility")
        self.assertNotIn("no-store", report["discovery"]["headers"]["cache_control"]["directives"])

    def test_no_store_or_no_cache_with_argument_is_incompatible(self):
        for value in ("no-store=", 'no-cache="Set-Cookie"'):
            headers = [("Content-Type", "application/json"), ("Cache-Control", value)]
            with self.subTest(value=value):
                report = self.observe(response(200, headers, discovery()), response(200, headers, jwks()))
                self.assertEqual(report["outcome"]["classification"], "observed-incompatibility")

    def test_missing_pkce_s256_or_rfc9207_iss_is_incompatible(self):
        report = self.observe(
            response(200, KEYCLOAK_LIKE_HEADERS, discovery(
                code_challenge_methods_supported=["plain"],
                authorization_response_iss_parameter_supported=False,
            )),
            response(200, KEYCLOAK_LIKE_HEADERS, jwks()),
        )
        self.assertEqual(report["outcome"]["classification"], "observed-incompatibility")
        self.assertIn("discovery code_challenge_methods_supported lacks S256", report["outcome"]["incompatibilities"])
        self.assertIn("discovery authorization_response_iss_parameter_supported is not true", report["outcome"]["incompatibilities"])

    def test_other_realm_is_a_fixture_failure(self):
        report = self.observe(response(200, KEYCLOAK_LIKE_HEADERS, discovery(jwks_uri="http://127.0.0.1:8080/realms/other/certs")),
                              response(200, KEYCLOAK_LIKE_HEADERS, jwks()))
        self.assertIn("fixture: discovery does not describe the fixed local realm", report["outcome"]["failures"])

    def test_private_key_material_is_a_fixture_failure(self):
        key = {"kty": "RSA", "n": "AQAB", "e": "AQAB", "d": "AQAB"}
        report = self.observe(response(200, KEYCLOAK_LIKE_HEADERS, discovery()),
                              response(200, KEYCLOAK_LIKE_HEADERS, jwks(key)))
        self.assertIn("fixture: JWKS is not a public key set", report["outcome"]["failures"])

    def test_unavailable_jwks_is_a_fixture_failure(self):
        report = self.observe(response(200, KEYCLOAK_LIKE_HEADERS, discovery()), response(404))
        self.assertIn("fixture: JWKS document unavailable", report["outcome"]["failures"])

    def test_redirecting_discovery_never_becomes_ready(self):
        r = relay(response(302, [("Location", "http://elsewhere.invalid/")]))
        self.addCleanup(r.close)
        with self.assertRaisesRegex(observe.Failure, "deadline"):
            observe.observe(r.argv, 0)

    def test_report_never_echoes_provider_values(self):
        canary = "canary-7f3a"
        headers = KEYCLOAK_LIKE_HEADERS + [
            ("X-Unknown", canary), ("Age", canary), ("Date", canary),
            ("Cache-Control", f"{canary}={canary}, max-age={canary}, private={canary}"),
            ("Content-Type", f"application/json; {canary}=1"),
        ]
        document = discovery(
            token_endpoint_auth_methods_supported=[canary, "client_secret_basic"],
            code_challenge_methods_supported=[canary],
            authorization_response_iss_parameter_supported=canary,
            issuer=canary, extra={canary: canary},
        )
        key = {"kid": canary, "kty": canary, "alg": canary, "use": canary, "n": canary, "x5c": [canary]}
        report = self.observe(response(200, headers, document), response(200, headers, jwks(key)))
        self.assertNotIn(canary, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
