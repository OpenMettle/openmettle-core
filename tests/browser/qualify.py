"""Drive runner Chrome over its private DevTools pipe. Only fixed phase names and fixed
failure kinds reach stderr."""
import contextlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


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

    def wait_for(self, expression, phase):
        deadline = time.monotonic() + 12
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


def journey(browser, app, issuer, enter):
    version = browser.call("Browser.getVersion")["product"]
    if not re.fullmatch(r"(HeadlessChrome|Chrome)/[0-9]+(?:\.[0-9]+){3}", version):
        raise Failure("unexpected browser version")
    print(f"Browser runtime {version}", flush=True)
    enter("browser target setup")
    target = browser.call("Target.createTarget", url="about:blank")["targetId"]
    browser.session = browser.call("Target.attachToTarget", targetId=target, flatten=True)["sessionId"]

    def page(origin, path, control):
        browser.wait_for(
            f"location.origin === {json.dumps(origin)} && location.pathname === '{path}' && "
            f"document.readyState === 'complete' && !!document.getElementById('{control}')",
            f"document did not commit at {path}")

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


def run(app, issuer, home, enter):
    enter("runner trust store")
    # Allowlist the child environment. Browser profile, NSS, cache, and crash files are private.
    env = {"HOME": str(home), "TMPDIR": str(home), "PATH": os.environ["PATH"]}
    db = home / ".local/share/pki/nssdb"
    db.mkdir(parents=True)
    certutil = ["certutil", "-d", f"sql:{db}"]
    for args, data in [(["-N", "--empty-password"], b""),
                       (["-A", "-a", "-t", "C,,", "-n", "fixture"], sys.stdin.buffer.read())]:
        subprocess.run(certutil + args, input=data, env=env, check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rules = "MAP app.relying.test 127.0.0.1, MAP issuer.example.test 127.0.0.1, MAP * ~NOTFOUND"
    # Chrome uses descriptors 3 and 4 for NUL-delimited commands and responses.
    # Save stdin and stdout there, then disconnect normal browser logs from the pipe.
    command = ["sh", "-c", 'exec 3<&0 4>&1 </dev/null >/dev/null; exec "$@"', "chrome-pipe",
               "google-chrome", "--headless", "--remote-debugging-pipe", "--no-first-run",
               "--disable-background-networking", "--no-proxy-server",
               f"--host-resolver-rules={rules}", f"--user-data-dir={home / 'profile'}"]
    parent, child = socket.socketpair()
    enter("browser start")
    with parent, child:
        process = subprocess.Popen(command, env=env, stdin=child, stdout=child,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        child.close()
        try:
            parent.settimeout(12)
            journey(DevTools(parent), app, issuer, enter)
            enter("browser shutdown")
        finally:
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


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(75)
    progress = Progress()
    try:
        with tempfile.TemporaryDirectory(prefix="om-browser-") as directory:
            run(*sys.argv[1:], Path(directory), progress.enter)
    except Failure as exc:
        sys.exit(str(exc))
    except Exception as exc:
        sys.exit(unexpected(exc, progress.phase))
