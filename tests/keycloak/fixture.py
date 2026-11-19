"""V1-04 fixture for the hosted Keycloak sign-in qualification. See README.md beside this file.

Three commands prepare what the pinned provider container and the Rust test read:

    fixture.py prepare  --directory DIR             test CA, provider certificate, realm, accounts
    fixture.py settings --directory DIR --address A  auth settings document for the provider at A
    fixture.py wait     --directory DIR             discovery over TLS verified against the test CA

Every value is synthetic and made for one run. Passwords and keys are written only to files in
DIR and are never printed: output is fixed phase names and fixed failure phrases.
"""
import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time

REALM = "openmettle-qualification"
PROVIDER_HOST = "keycloak.provider.test"
PROVIDER_PORT = 8443
ISSUER = f"https://{PROVIDER_HOST}:{PROVIDER_PORT}/realms/{REALM}"
DISCOVERY_PATH = f"/realms/{REALM}/.well-known/openid-configuration"
ENDPOINTS = {
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
}
CLIENT_ID = "openmettle-browser"
# The application the Rust test serves on loopback. Its port is fixed because Keycloak
# registers the exact redirect URI before that test starts.
APPLICATION_ORIGIN = "https://app.relying.test:18443"
CALLBACK = f"{APPLICATION_ORIGIN}/callback"
# Synthetic identifiers. The users' IDs become the `sub` claims of their ID tokens.
PROVIDER_ID = "00000000-0000-4000-8000-0000000c0104"
ACCOUNTS = {
    # Seeded and approved with the ADR 0013 operator script before sign-in.
    "approved": {"username": "synthetic-approved", "subject": "00000000-0000-4000-8000-0000000000a1"},
    # No account: redeems a home invitation with its one-time code (ADR 0022).
    "invited": {"username": "synthetic-invited", "subject": "00000000-0000-4000-8000-0000000000b2"},
}
# ADR 0011 amendment: an explicit reuse window for documents that refuse caching, at least
# the cooldown and at most 300 s. Both sign-ins of one run fit inside one window.
COOLDOWN_SECONDS = 60
UNCACHEABLE_REUSE_SECONDS = 300
FRESHNESS_SECONDS = 3600
# The only ranges the provider transport lets an operator allowlist for IPv4.
PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
MAX_DOCUMENT_BYTES = 64 * 1024
VALIDITY_DAYS = "2"

OPENSSL_CONFIG = f"""[req]
distinguished_name = subject
prompt = no
[subject]
CN = OpenMettle Keycloak qualification
[authority]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign
subjectKeyIdentifier = hash
[provider]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:{PROVIDER_HOST}
authorityKeyIdentifier = keyid
"""


class Failure(Exception):
    """Messages are fixed phrases; they never contain a generated or provider value."""


def phase(name):
    print(f"Fixture phase: {name}", flush=True)


def realm(passwords):
    """The realm import: one public PKCE client and the two synthetic users."""
    return {
        "realm": REALM,
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False,
        "clients": [{
            "clientId": CLIENT_ID,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": True,
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "consentRequired": False,
            "redirectUris": [CALLBACK],
            "webOrigins": [],
            "attributes": {
                # PKCE is required, and only with S256.
                "pkce.code.challenge.method": "S256",
                # RFC 9207: keep `iss` on the authorization response (also the default).
                "exclude.issuer.from.auth.response": "false",
            },
        }],
        "users": [{
            "id": account["subject"],
            "username": account["username"],
            "enabled": True,
            # A complete profile, so the default user profile asks for nothing at sign-in.
            "email": f"{account['username']}@example.test",
            "emailVerified": True,
            "firstName": "Synthetic",
            "lastName": name.capitalize(),
            "credentials": [{"type": "password", "value": passwords[name], "temporary": False}],
        } for name, account in ACCOUNTS.items()],
    }


def private_address(text):
    """One IPv4 address inside a range the transport lets an operator allowlist."""
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        raise Failure("provider address is not a private IPv4 address") from None
    if str(address) != text or not any(address in network for network in PRIVATE_NETWORKS):
        raise Failure("provider address is not a private IPv4 address")
    return address


def settings(directory, address):
    """The version-2 auth settings document (ADRs 0015 and 0020) for the provider at
    `address`. It names the test CA as the only trust and that one address as the only
    permitted private range."""
    rate = {"burst": 8, "interval_milliseconds": 1000}
    return {
        "version": 2,
        "login": {
            "lifetime_seconds": 300,
            "keys": {"active": {"id": "qualification", "path": str(directory / "login-key.bin")},
                     "decrypt_only": []},
        },
        "id_token": {"max_issued_at_age_seconds": 300, "future_skew_seconds": 60},
        "provider_refresh": {
            "freshness_seconds": FRESHNESS_SECONDS,
            "cooldown_seconds": COOLDOWN_SECONDS,
            "uncacheable_reuse_seconds": UNCACHEABLE_REUSE_SECONDS,
            "deadline_milliseconds": 10000,
            "max_providers": 1,
            "max_callers": 8,
            "max_document_gets": 2,
        },
        "session": {"lifetime_seconds": 600, "retained_per_user": 4, "deadline_milliseconds": 10000},
        "providers": [{
            "id": PROVIDER_ID,
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "revision": "qualification-1",
            "authorization_endpoint": ENDPOINTS["authorization_endpoint"],
            "token_endpoint": ENDPOINTS["token_endpoint"],
            "discovery_url": f"https://{PROVIDER_HOST}:{PROVIDER_PORT}{DISCOVERY_PATH}",
            "jwks_url": ENDPOINTS["jwks_uri"],
            "callback": CALLBACK,
            "destination": "home",
            "private_cidrs": [f"{private_address(address)}/32"],
            "trust": {"roots": "bundle", "bundle_path": str(directory / "provider-ca.pem")},
        }],
        "browser": {
            "provider_id": PROVIDER_ID,
            "origin": APPLICATION_ORIGIN,
            "landing_path": "/app",
            "paths": {"initiation": "/login", "session_check": "/session", "logout": "/logout"},
            "rates": {name: dict(rate) for name in ("initiation", "callback", "session_check", "logout")},
            "max_in_flight": 8,
        },
    }


def openssl(*arguments):
    try:
        subprocess.run(["openssl", *arguments], check=True, timeout=60, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise Failure("required runner tool missing: openssl") from None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise Failure("openssl refused a certificate step") from None


def write(path, data, mode):
    """Create `path` with `mode`; an existing file is never replaced."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as file:
        file.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, mode)


def certificates(directory):
    """A CA and one server certificate for the provider host, both for this run only. The
    CA key signs that one certificate and is then removed."""
    work = directory / "work"
    work.mkdir(mode=0o700)
    config, ca_key, request = work / "openssl.cnf", work / "ca-key.pem", work / "provider.csr"
    write(config, OPENSSL_CONFIG, 0o600)
    key = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"]
    try:
        openssl(*key, str(ca_key))
        openssl("req", "-new", "-x509", "-key", str(ca_key), "-sha256", "-days", VALIDITY_DAYS,
                "-config", str(config), "-extensions", "authority",
                "-subj", "/CN=OpenMettle Keycloak qualification CA",
                "-out", str(directory / "provider-ca.pem"))
        openssl(*key, str(directory / "provider/tls-key.pem"))
        openssl("req", "-new", "-key", str(directory / "provider/tls-key.pem"), "-config", str(config),
                "-subj", f"/CN={PROVIDER_HOST}", "-out", str(request))
        openssl("x509", "-req", "-in", str(request), "-CA", str(directory / "provider-ca.pem"),
                "-CAkey", str(ca_key), "-set_serial", "2", "-sha256", "-days", VALIDITY_DAYS,
                "-extfile", str(config), "-extensions", "provider",
                "-out", str(directory / "provider/tls-certificate.pem"))
    finally:
        for leftover in (config, ca_key, request):
            leftover.unlink(missing_ok=True)
        work.rmdir()


def prepare(directory):
    """DIR is private to the runner user. `provider` and `import` are the two directories
    bind-mounted into the provider container, which runs as another user: they and their
    files are world-readable, and only the mounts expose them beyond DIR."""
    phase("private fixture directory")
    try:
        directory.mkdir(mode=0o700)
    except (FileExistsError, FileNotFoundError):
        raise Failure("fixture directory must be new, inside an existing directory") from None
    os.chmod(directory, 0o700)
    for mounted in ("provider", "import"):
        (directory / mounted).mkdir()
        os.chmod(directory / mounted, 0o755)

    phase("test CA and provider certificate")
    certificates(directory)
    for mounted in ("provider/tls-key.pem", "provider/tls-certificate.pem"):
        os.chmod(directory / mounted, 0o644)

    phase("synthetic accounts and realm import")
    passwords = {name: secrets.token_urlsafe(24) for name in ACCOUNTS}
    write(directory / "import/realm.json", json.dumps(realm(passwords)), 0o644)
    accounts = {name: {**account, "password": passwords[name]} for name, account in ACCOUNTS.items()}
    write(directory / "accounts.json", json.dumps(accounts), 0o600)

    phase("login key")
    write(directory / "login-key.bin", secrets.token_bytes(32), 0o600)


def write_settings(directory, address):
    phase("auth settings document")
    if not (directory / "provider-ca.pem").is_file():
        raise Failure("fixture directory is not prepared")
    document = settings(directory.resolve(), address)
    try:
        write(directory / "auth-settings.json", json.dumps(document, indent=2) + "\n", 0o600)
    except FileExistsError:
        raise Failure("auth settings document already exists") from None


def discovery(ca, connect=socket.create_connection):
    """One GET of the realm's discovery document. TLS is verified against the test CA alone
    and for the provider host name. Returns a fixed outcome word."""
    context = ssl.create_default_context(cafile=str(ca))
    connection = http.client.HTTPSConnection(PROVIDER_HOST, PROVIDER_PORT, timeout=5, context=context)
    try:
        try:
            plain = connect((PROVIDER_HOST, PROVIDER_PORT), 5)
        except socket.gaierror:
            return "name unresolved"
        except OSError:
            return "no connection"
        try:
            connection.sock = context.wrap_socket(plain, server_hostname=PROVIDER_HOST)
        except ssl.SSLCertVerificationError:
            plain.close()
            return "certificate refused"
        except OSError:
            plain.close()
            return "no TLS session"
        connection.request("GET", DISCOVERY_PATH, headers={"Accept": "application/json"})
        response = connection.getresponse()
        body = response.read(MAX_DOCUMENT_BYTES + 1)
        if response.status != 200:
            return "not served"
    except (OSError, http.client.HTTPException):
        return "no response"
    finally:
        connection.close()
    try:
        document = json.loads(body) if len(body) <= MAX_DOCUMENT_BYTES else None
    except ValueError:
        document = None
    expected = {"issuer": ISSUER, **ENDPOINTS}
    if not isinstance(document, dict) or any(document.get(k) != v for k, v in expected.items()):
        return "other realm"
    return "served"


def wait(directory, deadline_seconds, probe=discovery, sleep=time.sleep):
    """Wait until the provider serves the fixture realm's discovery document."""
    phase("provider readiness")
    deadline = time.monotonic() + deadline_seconds
    while True:
        outcome = probe(directory / "provider-ca.pem")
        if outcome == "served":
            return
        # Neither changes while the provider starts, so waiting would only hide them.
        if outcome == "certificate refused":
            raise Failure("provider certificate was not accepted under the test CA")
        if outcome == "other realm":
            raise Failure("provider discovery does not describe the fixture realm")
        if time.monotonic() >= deadline:
            raise Failure(f"provider did not serve discovery before the deadline (last: {outcome})")
        sleep(2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "settings", "wait"):
        command = commands.add_parser(name)
        command.add_argument("--directory", type=Path, required=True)
        if name == "settings":
            command.add_argument("--address", required=True, help="the provider container's IPv4 address")
        if name == "wait":
            command.add_argument("--deadline", type=int, default=240, help="seconds to wait for discovery")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "prepare":
            prepare(args.directory)
        elif args.command == "settings":
            write_settings(args.directory, args.address)
        else:
            wait(args.directory, args.deadline)
    except Failure as failure:
        print(f"Fixture failed: {failure}", file=sys.stderr)
        return 1
    phase("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
