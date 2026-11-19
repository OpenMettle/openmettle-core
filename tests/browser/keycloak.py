"""Sign in through a real Keycloak login form with runner Chrome (V1-04).

    keycloak.py APPLICATION_ORIGIN ISSUER < input.json

Standard input is one JSON object: `authorities` (PEM certificates Chrome may trust),
`username`, `password` and `invitation_code` (a string, or null for none). The credentials
and the code travel only over stdin and Chrome's private DevTools pipe. Only fixed phase
names and fixed failure kinds reach stderr, as in `qualify.py`.
"""
import ipaddress
import json
import re
import socket
import sys
from urllib.parse import urlsplit

from qualify import (Failure, Navigating, committed, drive, execute, not_committed, open_target,
                     session_lifecycle)

MAX_INPUT_BYTES = 1024 * 1024
# Keycloak renders its first login page and answers the code exchange more slowly than the
# in-process fixture, most of all on a cold server.
PROVIDER_SECONDS = 30
HARNESS_SECONDS = 100
HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
# The application's fixed refusal lines (src/browser_auth/handoff.rs). A page showing one of
# them is reported by that constant; no other page text is ever reported.
REFUSALS = (
    "login origin refused",
    "login request refused",
    "login response refused; restart login",
    "login browser binding missing or superseded; restart login",
    "login refused. Start a new login.",
    "login unavailable; restart login",
)
FORM_CONTROLS = ("username", "password", "kc-login")


def site(url, path_allowed):
    """`(origin, host, port, path)` of a canonical HTTPS URL, with the origin as browsers
    serialize it. The host later enters a Chrome resolver rule, so its characters are fixed."""
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise Failure("harness site invalid") from None
    path = parts.path
    if (parts.scheme != "https" or not host or not HOST.fullmatch(host) or parts.query
            or parts.fragment or "@" in parts.netloc or (path and not path_allowed)
            or path.endswith("/") or not re.fullmatch(r"[A-Za-z0-9/_.-]*", path)):
        raise Failure("harness site invalid")
    origin = f"https://{host}" + ("" if port in (None, 443) else f":{port}")
    if origin + path != url:
        raise Failure("harness site invalid")
    return origin, host, port or 443, path


def provider_address(host, port, lookup=socket.getaddrinfo):
    """The one IPv4 address the runner's resolver gives for the provider. The OpenMettle
    transport under test resolves the same name the same way."""
    try:
        answers = {answer[4][0] for answer in lookup(host, port, socket.AF_INET, socket.SOCK_STREAM)}
        address, = answers
        return str(ipaddress.IPv4Address(address))
    except (OSError, ValueError):
        raise Failure("provider address not resolved") from None


def resolver_rules(application_host, provider_host, address):
    """The application on loopback, the provider at its address, and nothing else."""
    return f"MAP {application_host} 127.0.0.1, MAP {provider_host} {address}, MAP * ~NOTFOUND"


def parse_input(raw):
    """The four members and nothing else. Messages never repeat any of the input."""
    try:
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError
        value = json.loads(raw)
        authorities, code = value["authorities"], value["invitation_code"]
        texts = [value["username"], value["password"], *authorities] + ([] if code is None else [code])
        if (set(value) != {"authorities", "username", "password", "invitation_code"}
                or not isinstance(authorities, list) or not authorities
                or not all(isinstance(text, str) and text for text in texts)):
            raise ValueError
        return [authority.encode("ascii") for authority in authorities], value
    except (ValueError, KeyError, TypeError):
        raise Failure("harness input invalid") from None


def refusal(browser, application):
    """The application's fixed refusal line shown by the current page, if it shows one."""
    try:
        shown = browser.evaluate(
            f"location.origin === {json.dumps(application)} ? document.body?.innerText.trim() : null")
    except Navigating:
        return None
    return shown if shown in REFUSALS else None


def arrive(browser, application, wait, phrase):
    """Run `wait`, which fails with `phrase` when its document never appears. If the
    application shows one of its fixed refusal lines instead, report that line: it names the
    step that refused. Every other failure passes through unchanged."""
    try:
        wait()
    except Failure as failure:
        line = refusal(browser, application) if str(failure) == phrase else None
        if line is None:
            raise
        raise Failure(f"application answered: {line}") from None


def journey(browser, application, provider, realm_path, account, enter):
    enter("browser target setup")
    open_target(browser)
    enter("login page")
    browser.call("Page.navigate", url=application + "/")
    committed(browser, application, "/", "login")
    if account["invitation_code"] is not None:
        enter("invitation code entry")
        browser.evaluate("document.getElementById('invitation').value = "
                         f"{json.dumps(account['invitation_code'])}; true")

    enter("provider login form")
    browser.click("login")
    no_form = "provider login form did not load"
    arrive(browser, application, lambda: browser.wait_for(
        f"location.origin === {json.dumps(provider)} && "
        f"location.pathname.startsWith({json.dumps(realm_path + '/')}) && "
        "document.readyState === 'complete' && "
        f"{json.dumps(FORM_CONTROLS)}.every(id => !!document.getElementById(id))",
        no_form, PROVIDER_SECONDS), no_form)

    enter("provider credentials")
    browser.evaluate(
        f"document.getElementById('username').value = {json.dumps(account['username'])}; "
        f"document.getElementById('password').value = {json.dumps(account['password'])}; true")
    enter("callback and landing")
    browser.click("kc-login")
    arrive(browser, application,
           lambda: committed(browser, application, "/app", "logout", PROVIDER_SECONDS),
           not_committed("/app"))
    session_lifecycle(browser, application, enter)


def run(application_url, issuer, home, enter, raw=None, lookup=socket.getaddrinfo):
    enter("harness input")
    application, application_host, _, _ = site(application_url, path_allowed=False)
    provider, provider_host, provider_port, realm_path = site(issuer, path_allowed=True)
    if not realm_path or provider_host == application_host:
        raise Failure("harness site invalid")
    authorities, account = parse_input(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1) if raw is None else raw)
    rules = resolver_rules(application_host, provider_host,
                           provider_address(provider_host, provider_port, lookup))
    drive(lambda browser: journey(browser, application, provider, realm_path, account, enter),
          authorities, rules, home, enter)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: keycloak.py APPLICATION_ORIGIN ISSUER < input.json")
    execute(lambda home, enter: run(sys.argv[1], sys.argv[2], home, enter), HARNESS_SECONDS)
