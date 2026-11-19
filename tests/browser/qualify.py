"""Drive runner Chrome over its private DevTools pipe. Only fixed phase names and fixed
failure kinds reach stderr."""
import base64
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit


class Failure(Exception):
    """Messages must never contain browser output."""


class Navigating(Failure):
    """The renderer changed while a document predicate was in flight."""


class Progress:
    """The fixed phase in progress, for errors that carry no phase of their own."""

    phase = "harness setup"

    def enter(self, phase):
        self.phase = phase


def unexpected(error, phase):
    """Describe a non-Failure error by its kind and phase only, never by its own text."""
    if isinstance(error, (TimeoutError, socket.timeout, subprocess.TimeoutExpired)):
        kind = "timed out"
    elif isinstance(error, ConnectionError):
        # Linux resets the pipe when Chrome exits with a command still unread.
        kind = "browser pipe lost"
    elif isinstance(error, FileNotFoundError):
        kind = "required runner tool missing"
    elif isinstance(error, subprocess.CalledProcessError):
        kind = "runner tool refused"
    else:
        kind = "browser harness failed"
    return f"{kind} during {phase}"


class DevTools:
    MAX_PACKET_BYTES = 1024 * 1024

    def __init__(self, connection):
        self.connection = connection
        self.pending = b""
        self.sequence = 0
        self.session = None

    def call(self, method, **params):
        self.sequence += 1
        message = dict(id=self.sequence, method=method, params=params)
        if self.session:
            message["sessionId"] = self.session
        self.connection.sendall(json.dumps(message).encode() + b"\0")
        while True:
            end = self.pending.find(b"\0")
            while end < 0:
                if len(self.pending) > self.MAX_PACKET_BYTES:
                    raise Failure("browser pipe packet oversized")
                data = self.connection.recv(16384)
                if not data:
                    raise Failure("browser pipe closed")
                self.pending += data
                end = self.pending.find(b"\0")
            if end > self.MAX_PACKET_BYTES:
                raise Failure("browser pipe packet oversized")
            packet, self.pending = self.pending[:end], self.pending[end + 1:]
            reply = json.loads(packet)
            if reply.get("id") == self.sequence:
                if "error" in reply:
                    if reply["error"].get("message") in (
                        "Execution context was destroyed.", "Inspected target navigated or closed"
                    ):
                        raise Navigating("document changed during browser command")
                    raise Failure("browser command refused")
                return reply["result"]

    def evaluate(self, expression):
        result = self.call("Runtime.evaluate", expression=expression, awaitPromise=True,
                           returnByValue=True, userGesture=True)
        if "exceptionDetails" in result:
            raise Failure("page action failed")
        return result["result"].get("value")

    def wait_for(self, expression, phase, seconds=12):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if self.evaluate(expression) is True:
                    return
            except Navigating:
                pass  # Only read-only document predicates can be retried.
            time.sleep(0.05)
        raise Failure(phase)

    def click(self, element):
        # Finish this command before the click can replace the renderer.
        self.evaluate(f"setTimeout(() => document.getElementById('{element}').click(), 0); true")


START_ATTEMPTS = 2


def start(launch, attempts=START_ATTEMPTS):
    """Return the first browser that answers its version request, with its close action.

    Runner Chrome occasionally never answers its first command. Only that silent start is
    retried: the browser is closed and `launch` is called again with the next attempt
    number, which selects a fresh profile. A browser that exits or loses its pipe, every
    other failure, and everything after the browser has answered are never retried.
    """
    for attempt in range(1, attempts + 1):
        browser, close = launch(attempt)
        try:
            version = browser.call("Browser.getVersion")["product"]
        except TimeoutError:
            close()
            if attempt == attempts:
                raise
            print("Browser start retried", flush=True)
            continue
        except BaseException:
            close()
            raise
        if not re.fullmatch(r"(HeadlessChrome|Chrome)/[0-9]+(?:\.[0-9]+){3}", version):
            close()
            raise Failure("unexpected browser version")
        print(f"Browser runtime {version}", flush=True)
        return browser, close


def open_target(browser):
    """Attach to one new blank page. Every later command addresses it."""
    target = browser.call("Target.createTarget", url="about:blank")["targetId"]
    browser.session = browser.call("Target.attachToTarget", targetId=target, flatten=True)["sessionId"]


def committed(browser, origin, path, control, seconds=12):
    """Wait for the complete document at `path` on `origin` that has the `control` element."""
    browser.wait_for(
        f"location.origin === {json.dumps(origin)} && location.pathname === '{path}' && "
        f"document.readyState === 'complete' && !!document.getElementById('{control}')",
        not_committed(path), seconds)


def not_committed(path):
    """The fixed phrase `committed` fails with for `path`."""
    return f"document did not commit at {path}"


def session_lifecycle(browser, app, enter):
    """On the landing page: the exact landing URL, a valid session, logout, then a refused check."""
    if browser.evaluate(f"location.href === {json.dumps(app + '/app')}") is not True:
        raise Failure("unexpected landing URL")
    enter("issued session check")
    if browser.evaluate("fetch('/session').then(r => r.status)") != 204:
        raise Failure("issued session check")
    enter("logout")
    browser.click("logout")
    browser.wait_for("document.forms[0].dataset.status === '204'", "logout acknowledgement")
    enter("signed-out session check")
    if browser.evaluate("fetch('/session').then(async r => r.status === 403 && "
                        "(await r.text()).trim() === 'session not valid')") is not True:
        raise Failure("signed-out session check")


def journey(browser, app, issuer, enter, link=None, ca=None):
    enter("browser target setup")
    open_target(browser)

    def page(origin, path, control):
        committed(browser, origin, path, control)

    if link:
        native_journey(browser, app, issuer, enter, link, ca, page)
        return

    enter("wrong-origin form")
    browser.call("Page.navigate", url=issuer + "/wrong")
    page(issuer, "/wrong", "wrong")
    browser.click("wrong")
    browser.wait_for(f"location.origin === {json.dumps(app)} && location.pathname === '/login' && "
                     "document.body?.innerText.trim() === 'login origin refused'",
                     "wrong-origin form denial")

    enter("login page")
    browser.call("Page.navigate", url=app + "/")
    page(app, "/", "login")
    enter("provider authorization")
    browser.click("login")
    page(issuer, "/authorize", "approve")
    enter("callback and landing")
    browser.click("approve")
    page(app, "/app", "logout")
    session_lifecycle(browser, app, enter)


def native_journey(browser, app, issuer, enter, link, ca, page):
    enter("native confirmation page")
    verifier = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urlencode(dict(client_id="synthetic.mobile", redirect_uri=link, response_type="code",
                           code_challenge=challenge, code_challenge_method="S256", state=state))
    browser.call("Page.navigate", url=f"{app}/auth/native/authorize?{query}")
    page(app, "/auth/native/authorize", "confirm")
    enter("provider authorization")
    # The form posts its one invitation_code field, left empty: no code was entered.
    browser.click("confirm")
    page(issuer, "/authorize", "approve")
    enter("native app link")
    browser.click("approve")
    browser.wait_for(f"location.origin + location.pathname === {json.dumps(link)} && "
                     "document.body?.innerText.trim() === 'synthetic app link'", "native HTTPS link")
    params = parse_qs(browser.evaluate("location.search.slice(1)"), strict_parsing=True)
    if (set(params) != {"iss", "code", "state"} or params["iss"] != [app] or
            params["state"] != [state] or len(params["code"]) != 1 or len(params["code"][0]) != 43):
        raise Failure("native callback binding")

    # Independent HTTPS client, empty cookie jar, one trusted ephemeral CA and loopback resolution.
    target = urlsplit(app)
    trust = ssl.create_default_context(cadata=ca.decode("ascii"))

    def backchannel(method, path, body=None, headers=None):
        conn = http.client.HTTPSConnection(target.hostname, target.port, context=trust, timeout=4)
        conn._create_connection = lambda *_: socket.create_connection(("127.0.0.1", target.port), 4)
        try:
            conn.request(method, "/auth/native/" + path, body, headers or {})
            reply = conn.getresponse()
            if reply.getheader("Cache-Control") != "no-store" or reply.getheader("Set-Cookie"):
                raise Failure("native response headers")
            return reply.status, reply.read(4096)
        finally:
            conn.close()

    enter("native code redemption")
    payload = json.dumps(dict(grant_type="authorization_code", iss=app, client_id="synthetic.mobile",
                              redirect_uri=link, code=params["code"][0], code_verifier=verifier))
    status, body = backchannel("POST", "token", payload, {"Content-Type": "application/json"})
    if status != 200:
        raise Failure("native HTTPS redemption")
    token = json.loads(body)
    if set(token) != {"token_type", "access_token"} or token["token_type"] != "Bearer":
        raise Failure("native token response")
    enter("native session lifecycle")
    headers = {"Authorization": "Bearer " + token["access_token"]}
    for method, path, expected in [("GET", "session", 204), ("POST", "logout", 204), ("GET", "session", 403)]:
        if backchannel(method, path, headers=headers)[0] != expected:
            raise Failure("native HTTPS session lifecycle")



# The two fixture sites on loopback; every other name fails to resolve.
RULES = "MAP app.relying.test 127.0.0.1, MAP issuer.example.test 127.0.0.1, MAP * ~NOTFOUND"
NATIVE_RULES = ("MAP app.relying.test 127.0.0.1, MAP issuer.example.test 127.0.0.1, "
                "MAP links.relying.test 127.0.0.1, MAP * ~NOTFOUND")


def chrome(home, attempt, rules=RULES):
    """The Chrome command for one start attempt. Each attempt has its own profile."""
    # Chrome uses descriptors 3 and 4 for NUL-delimited commands and responses.
    # Save stdin and stdout there, then disconnect normal browser logs from the pipe.
    return ["sh", "-c", 'exec 3<&0 4>&1 </dev/null >/dev/null; exec "$@"', "chrome-pipe",
            "google-chrome", "--headless", "--remote-debugging-pipe", "--no-first-run",
            "--disable-background-networking", "--no-proxy-server",
            f"--host-resolver-rules={rules}", f"--user-data-dir={home / f'profile-{attempt}'}"]


def run(app, issuer, home, enter, link=None):
    ca = sys.stdin.buffer.read()
    drive(lambda browser: journey(browser, app, issuer, enter, link, ca),
          [ca], NATIVE_RULES if link else RULES, home, enter)


def drive(journey, authorities, rules, home, enter):
    """Start Chrome with `authorities` (one PEM certificate each) as its only added trust and
    `rules` as its only name resolution, run `journey(browser)`, then stop Chrome."""
    enter("runner trust store")
    # Allowlist the child environment. Browser profile, NSS, cache, and crash files are private.
    env = {"HOME": str(home), "TMPDIR": str(home), "PATH": os.environ["PATH"]}
    db = home / ".local/share/pki/nssdb"
    db.mkdir(parents=True)
    certutil = ["certutil", "-d", f"sql:{db}"]
    additions = [(["-A", "-a", "-t", "C,,", "-n", f"fixture-{index}"], authority)
                 for index, authority in enumerate(authorities)]
    for args, data in [(["-N", "--empty-password"], b"")] + additions:
        subprocess.run(certutil + args, input=data, env=env, check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def launch(attempt):
        parent, child = socket.socketpair()
        try:
            with child:
                process = subprocess.Popen(chrome(home, attempt, rules), env=env, stdin=child,
                                           stdout=child,
                                           stderr=subprocess.DEVNULL, start_new_session=True)
        except BaseException:
            parent.close()
            raise
        parent.settimeout(12)
        return DevTools(parent), lambda: stop(parent, process)

    enter("browser start")
    browser, close = start(launch)
    try:
        journey(browser)
        enter("browser shutdown")
    finally:
        close()


def stop(parent, process):
    # Closing the debugging pipe requests normal Chrome shutdown. On timeout
    # the unreaped leader still reserves the group ID created by this harness.
    parent.close()
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def interrupted(*_):
    raise Failure("browser harness timed out or interrupted")


def execute(run, seconds):
    """Call `run(home, enter)` with a private temporary home under one alarm. A failure exits
    with one fixed line: its own phrase, or its kind and the phase in progress."""
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(seconds)
    progress = Progress()
    try:
        with tempfile.TemporaryDirectory(prefix="om-browser-") as directory:
            run(Path(directory), progress.enter)
    except Failure as exc:
        sys.exit(str(exc))
    except Exception as exc:
        sys.exit(unexpected(exc, progress.phase))


if __name__ == "__main__":
    execute(lambda home, enter: run(sys.argv[1], sys.argv[2], home, enter, *sys.argv[3:]), 75)
