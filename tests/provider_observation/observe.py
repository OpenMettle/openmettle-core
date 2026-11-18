"""V1-04 wire observation of a pinned stock OIDC provider's discovery and JWKS documents.

This is not a login test. It requests two fixed local document paths once each, records
bounded allowlisted facts and asserts the incompatibilities that upstream source predicts.
Raw documents, key material, identifiers and unrecognized header values never leave this
process: every reported string is a constant or an allowlisted token.
"""
import argparse
import http.client
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from urllib.request import parse_http_list

# Must equal the production document request in src/provider_http.rs (checked by tests).
ACCEPT = "application/json, application/jwk-set+json"
# The provider's loopback inside its own network namespace. Nothing is resolved or proxied.
ORIGIN = "http://127.0.0.1:8080"
HOST = "127.0.0.1:8080"
REALM = "master"
ISSUER = f"{ORIGIN}/realms/{REALM}"
DISCOVERY_PATH = f"/realms/{REALM}/.well-known/openid-configuration"
# Fixed independently of the discovery document; a returned jwks_uri is compared, never followed.
JWKS_PATH = f"/realms/{REALM}/protocol/openid-connect/certs"
AUTHORIZATION_URL = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
# Same ceiling as auth::MAX_JWKS_BYTES, applied to both documents.
MAX_DOCUMENT_BYTES = 64 * 1024
REQUEST_SECONDS = 20

# Reads one HTTP/1.1 response from a socket opened by the provider image's own shell.
# The request bytes arrive on stdin; the response is streamed to stdout unmodified.
RELAY = "exec 3<>/dev/tcp/127.0.0.1/8080 || exit 97; cat >&3 && exec cat <&3"

MEDIA_TYPES = {"application/json", "application/jwk-set+json", "application/jwt"}
CACHE_DIRECTIVES = {
    "no-store", "no-cache", "max-age", "s-maxage", "public", "private", "must-revalidate",
    "proxy-revalidate", "no-transform", "stale-if-error", "stale-while-revalidate", "immutable",
    "must-understand",
}
AUTH_METHODS = {
    "none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt",
    "tls_client_auth", "self_signed_tls_client_auth",
}
PKCE_METHODS = {"S256", "plain"}
KEY_TYPES = {"RSA", "EC", "OKP", "oct"}
KEY_USES = {"sig", "enc"}
KEY_ALGORITHMS = {
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
    "Ed25519", "RSA-OAEP", "RSA-OAEP-256", "RSA1_5", "ECDH-ES",
}
PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
IMF_FIXDATE = re.compile(
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT"
)


class Failure(Exception):
    """Messages are fixed phrases; they never contain provider output."""


def request_bytes(path):
    """Use the production Accept value and request EOF after the single response."""
    return f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nAccept: {ACCEPT}\r\nConnection: close\r\n\r\n".encode("ascii")


class _Pipe:
    """Lets http.client parse a response from a subprocess stdout."""

    def __init__(self, stream):
        self.stream = stream

    def makefile(self, mode, *args, **kwargs):
        return self.stream


def exchange(argv, path, seconds=REQUEST_SECONDS):
    """Send one GET through `argv` and parse one bounded response. Redirects are never followed."""
    deadline = time.monotonic() + seconds
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        watchdog = threading.Timer(seconds, proc.kill)
        watchdog.start()
        try:
            proc.stdin.write(request_bytes(path))
            proc.stdin.close()
            with http.client.HTTPResponse(_Pipe(proc.stdout), method="GET") as response:
                response.begin()
                if response.length is None:
                    body = response.read(MAX_DOCUMENT_BYTES + 1)
                elif response.length <= MAX_DOCUMENT_BYTES:
                    # read() enforces the declared length; read(limit) accepts an early EOF.
                    body = response.read()
                else:
                    raise Failure("document exceeds the size limit")
                if len(body) > MAX_DOCUMENT_BYTES:
                    raise Failure("document exceeds the size limit")
                if proc.wait() != 0 or time.monotonic() >= deadline:
                    raise Failure("relay did not complete before the deadline")
                return response.status, response.getheaders(), body
        except (http.client.HTTPException, OSError, ValueError):
            raise Failure("no complete HTTP response") from None
        finally:
            watchdog.cancel()
            proc.kill()
            watchdog.join()


def _values(headers, name):
    return [v for k, v in headers if k.lower() == name]


def _decimal(value):
    value = value.strip()
    return int(value) if value.isascii() and value.isdecimal() and len(value) <= 10 else "non-numeric"


def media_facts(values):
    if len(values) != 1:
        return {"count": len(values)}
    kind, *params = values[0].split(";")
    kind = kind.strip().lower()
    charset = [p for p in params if p.strip().lower() in ("charset=utf-8", 'charset="utf-8"')]
    return {
        "count": 1,
        "media_type": kind if kind in MEDIA_TYPES else "other",
        "charset_utf8": bool(charset),
        "other_parameters": len(params) - len(charset),
    }


def cache_facts(values):
    directives, unknown, repeated = {}, 0, 0
    for header in values:
        for item in parse_http_list(header):
            name, separator, argument = item.strip().partition("=")
            name = name.strip().lower()
            if not name:
                continue
            if name not in CACHE_DIRECTIVES:
                unknown += 1
                continue
            if name in directives:
                repeated += 1
            argument = argument.strip()
            if not separator:
                directives[name] = True
            elif name in ("max-age", "s-maxage", "stale-if-error", "stale-while-revalidate"):
                directives[name] = _decimal(argument.strip('"'))
            else:
                directives[name] = "argument"
    return {
        "count": len(values),
        "directives": dict(sorted(directives.items())),
        "repeated_directives": repeated,
        "unknown_directives": unknown,
    }


def header_facts(status, headers):
    dates = _values(headers, "date")
    ages = _values(headers, "age")
    return {
        "status": status,
        "content_type": media_facts(_values(headers, "content-type")),
        "date": {"count": len(dates), "imf_fixdate": len(dates) == 1 and bool(IMF_FIXDATE.fullmatch(dates[0].strip()))},
        "age": {"count": len(ages), "value": _decimal(ages[0]) if len(ages) == 1 else None},
        "cache_control": cache_facts(_values(headers, "cache-control")),
        "content_encoding_present": bool(_values(headers, "content-encoding")),
        "location_present": bool(_values(headers, "location")),
    }


def _reject_duplicates(pairs):
    names = [k for k, _ in pairs]
    if len(set(names)) != len(names):
        raise Failure("document repeats a member")
    return dict(pairs)


def parse_document(body):
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (ValueError, RecursionError):
        raise Failure("document is not JSON") from None
    if not isinstance(value, dict):
        raise Failure("document is not a JSON object")
    return value


def advertised(document, name, known):
    """Membership facts for a string array; unknown values are counted, never echoed."""
    if name not in document:
        return {"shape": "absent"}
    value = document[name]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        return {"shape": "invalid"}
    return {
        "shape": "array",
        "known": sorted({v for v in value if v in known}),
        "other": sum(1 for v in value if v not in known),
    }


def _includes(document, name, wanted):
    value = document.get(name)
    if not isinstance(value, list):
        return "absent" if value is None else "invalid"
    return wanted in value


def metadata_facts(document):
    iss = document.get("authorization_response_iss_parameter_supported", "absent")
    return {
        "issuer_matches_fixed": document.get("issuer") == ISSUER,
        "jwks_uri_matches_fixed": document.get("jwks_uri") == ORIGIN + JWKS_PATH,
        "authorization_endpoint_matches_fixed": document.get("authorization_endpoint") == AUTHORIZATION_URL,
        "token_endpoint_matches_fixed": document.get("token_endpoint") == TOKEN_URL,
        "token_endpoint_auth_methods_supported": advertised(document, "token_endpoint_auth_methods_supported", AUTH_METHODS),
        "code_challenge_methods_supported": advertised(document, "code_challenge_methods_supported", PKCE_METHODS),
        "authorization_response_iss_parameter_supported": iss if isinstance(iss, bool) or iss == "absent" else "invalid",
        "response_types_supported_includes_code": _includes(document, "response_types_supported", "code"),
        "response_modes_supported_includes_query": _includes(document, "response_modes_supported", "query"),
        "grant_types_supported_includes_authorization_code": _includes(document, "grant_types_supported", "authorization_code"),
        "id_token_signing_alg_values_supported_includes_RS256": _includes(document, "id_token_signing_alg_values_supported", "RS256"),
        "subject_types_supported_includes_public": _includes(document, "subject_types_supported", "public"),
    }


def _count(values, known):
    counts = {}
    for value in values:
        label = value if isinstance(value, str) and value in known else ("absent" if value is None else "other")
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def jwks_facts(document):
    keys = document.get("keys")
    if not isinstance(keys, list):
        return {"keys_shape": "absent" if keys is None else "invalid"}
    objects = [k for k in keys if isinstance(k, dict)]
    return {
        "keys_shape": "array",
        "key_count": len(keys),
        "non_object_keys": len(keys) - len(objects),
        "kty": _count([k.get("kty") for k in objects], KEY_TYPES),
        "alg": _count([k.get("alg") for k in objects], KEY_ALGORITHMS),
        "use": _count([k.get("use") for k in objects], KEY_USES),
        "rsa_rs256_signing_keys": sum(
            1 for k in objects
            if k.get("kty") == "RSA" and k.get("alg") in (None, "RS256") and k.get("use") in (None, "sig")
        ),
        "private_members_present": any(m in k for k in objects for m in PRIVATE_MEMBERS),
    }


def evaluate(discovery, jwks):
    """Fixture checks and source predictions. Each failure is a fixed phrase."""
    failures = []
    d_headers, d_meta = discovery["headers"], discovery.get("metadata")
    j_headers, j_keys = jwks["headers"], jwks.get("keys")
    if d_headers["status"] != 200 or d_meta is None:
        failures.append("fixture: discovery document unavailable")
    if j_headers["status"] != 200 or j_keys is None:
        failures.append("fixture: JWKS document unavailable")
    if d_meta is not None and not (d_meta["issuer_matches_fixed"] and d_meta["jwks_uri_matches_fixed"]):
        failures.append("fixture: discovery does not describe the fixed local realm")
    if j_keys is not None and (j_keys["keys_shape"] != "array" or j_keys["non_object_keys"] or j_keys["private_members_present"]):
        failures.append("fixture: JWKS is not a public key set")
    incompatibilities = []
    if d_meta is not None:
        methods = d_meta["token_endpoint_auth_methods_supported"]
        if methods["shape"] == "array" and "none" not in methods["known"]:
            incompatibilities.append("discovery token_endpoint_auth_methods_supported omits none")
        else:
            failures.append("prediction not observed: discovery advertises no array without none")
    if d_headers["cache_control"]["directives"].get("no-store") is True:
        incompatibilities.append("discovery Cache-Control includes no-store")
    else:
        failures.append("prediction not observed: discovery Cache-Control lacks no-store")
    return failures, incompatibilities


def observe(argv, deadline_seconds):
    """Waits for the provider to serve discovery, then takes one observation of each document."""
    deadline = time.monotonic() + deadline_seconds
    while True:
        try:
            status, headers, body = exchange(argv, DISCOVERY_PATH)
            if status == 200:
                break
        except Failure:
            pass
        if time.monotonic() >= deadline:
            raise Failure("provider did not serve discovery before the deadline")
        time.sleep(2)
    discovery = {"headers": header_facts(status, headers)}
    try:
        discovery["metadata"] = metadata_facts(parse_document(body))
    except Failure as error:
        discovery["error"] = str(error)
    status, headers, body = exchange(argv, JWKS_PATH)
    jwks = {"headers": header_facts(status, headers)}
    if status == 200:
        try:
            jwks["keys"] = jwks_facts(parse_document(body))
        except Failure as error:
            jwks["error"] = str(error)
    failures, incompatibilities = evaluate(discovery, jwks)
    return {
        "scope": "V1-04 provider document wire observation",
        "request": {"accept": ACCEPT, "redirects_followed": False, "returned_jwks_uri_followed": False},
        "transport": "loopback HTTP/1.1 inside the provider container network namespace; "
                     "not OpenMettle's HTTPS provider transport",
        "discovery": discovery,
        "jwks": jwks,
        "outcome": {
            "classification": "observed-incompatibility" if incompatibilities and not failures else "not-established",
            "incompatibilities": incompatibilities,
            "failures": failures,
            "login_attempted": False,
            "provider_support_claimed": False,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--container", required=True, help="running provider container name")
    parser.add_argument("--deadline", type=int, default=240, help="seconds to wait for discovery")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    relay = ["docker", "exec", "-i", args.container, "bash", "-c", RELAY]
    try:
        report = observe(relay, args.deadline)
    except Failure as error:
        report = {"scope": "V1-04 provider document wire observation", "outcome": {
            "classification": "not-established", "failures": [f"fixture: {error}"],
            "login_attempted": False, "provider_support_claimed": False}}
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["outcome"], indent=2, sort_keys=True))
    return 1 if report["outcome"]["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
