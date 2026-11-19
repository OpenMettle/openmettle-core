"""Exercise the private pipe and failure reporting without starting Chrome."""
import contextlib
import io
import json
import socket
import subprocess
import unittest

from qualify import DevTools, Failure, Progress, journey, start, unexpected

VERSION = b'{"id":1,"result":{"product":"Chrome/1.2.3.4"}}\0'


class Launches:
    """Fake browser launches: each attempt answers with its scripted bytes, or stays silent."""

    def __init__(self, test, *replies):
        self.replies, self.launched, self.closed = replies, [], []
        self.test = test

    def __call__(self, attempt):
        client, peer = socket.socketpair()
        self.test.addCleanup(client.close)
        self.test.addCleanup(peer.close)
        client.settimeout(0.05)
        if self.replies[attempt - 1]:
            peer.sendall(self.replies[attempt - 1])
        self.launched.append(attempt)
        return DevTools(client), lambda: self.closed.append(attempt)


class PrivatePipeTests(unittest.TestCase):
    def test_reads_only_matching_response_and_preserves_packet_boundary(self):
        client, peer = socket.socketpair()
        with client, peer:
            browser = DevTools(client)
            peer.sendall(b'{"method":"event"}\0{"id":1,"result":{"first":1}}\0'
                         b'{"id":2,"result":{"second":2}}\0')
            self.assertEqual(browser.call("Browser.getVersion"), {"first": 1})
            browser.session = "fixture"
            self.assertEqual(browser.call("Runtime.evaluate", expression="true"), {"second": 2})
            with peer.makefile("rb", buffering=0) as reader:
                packet = bytearray()
                while packet.count(0) < 2:
                    packet.extend(reader.read(1))
            first, second = map(json.loads, packet.rstrip(b"\0").split(b"\0"))
            self.assertNotIn("sessionId", first)
            self.assertEqual(second["sessionId"], "fixture")

    def test_protocol_error_does_not_expose_browser_message(self):
        client, peer = socket.socketpair()
        with client, peer:
            peer.sendall(b'{"id":1,"error":{"message":"sensitive fixture detail"}}\0')
            with self.assertRaisesRegex(Failure, "^browser command refused$"):
                DevTools(client).call("Runtime.evaluate")

    def test_packet_limit_applies_to_each_complete_message(self):
        client, peer = socket.socketpair()
        with client, peer:
            browser = DevTools(client)
            packet = b'{"id":1,"result":{}}'
            browser.MAX_PACKET_BYTES = len(packet)
            peer.sendall(packet + b'\0' + packet.replace(b':1,', b':2,') + b' \0')
            self.assertEqual(browser.call("Browser.getVersion"), {})
            with self.assertRaisesRegex(Failure, "^browser pipe packet oversized$"):
                browser.call("Browser.getVersion")

    def test_page_exception_does_not_expose_exception_detail(self):
        client, peer = socket.socketpair()
        with client, peer:
            peer.sendall(b'{"id":1,"result":{"exceptionDetails":{"text":"sensitive"}}}\0')
            with self.assertRaisesRegex(Failure, "^page action failed$"):
                DevTools(client).evaluate("true")


class StartPhaseTests(unittest.TestCase):
    def test_silent_browser_is_reported_by_the_phase_in_progress(self):
        progress = Progress()
        progress.enter("browser start")
        # The browser answers its version, then never answers again.
        with contextlib.redirect_stdout(io.StringIO()):
            browser, _ = start(Launches(self, VERSION))
        with self.assertRaises(TimeoutError) as raised:
            journey(browser, "https://app.test", "https://issuer.test", progress.enter)
        self.assertEqual(unexpected(raised.exception, progress.phase),
                         "timed out during browser target setup")

    def test_browser_that_never_answers_is_a_start_timeout(self):
        progress = Progress()
        progress.enter("browser start")
        launches = Launches(self, None, None)
        with self.assertRaises(TimeoutError) as raised, \
                contextlib.redirect_stdout(io.StringIO()):
            start(launches)
        self.assertEqual(unexpected(raised.exception, progress.phase),
                         "timed out during browser start")
        # Both attempts were made and both browsers were closed.
        self.assertEqual((launches.launched, launches.closed), ([1, 2], [1, 2]))


class StartRetryTests(unittest.TestCase):
    def test_a_silent_start_is_retried_once(self):
        launches = Launches(self, None, VERSION)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            browser, close = start(launches)
        self.assertEqual((launches.launched, launches.closed), ([1, 2], [1]))
        self.assertEqual(output.getvalue(),
                         "Browser start retried\nBrowser runtime Chrome/1.2.3.4\n")
        close()
        self.assertEqual(launches.closed, [1, 2])

    def test_a_browser_that_answers_is_not_relaunched(self):
        launches = Launches(self, VERSION, VERSION)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            start(launches)
        self.assertEqual((launches.launched, launches.closed), ([1], []))
        self.assertNotIn("retried", output.getvalue())

    def test_a_refused_or_unexpected_start_is_never_retried(self):
        for reply, message in [
            (b'{"id":1,"error":{"message":"sensitive"}}\0', "browser command refused"),
            (b'{"id":1,"result":{"product":"Other/1"}}\0', "unexpected browser version"),
        ]:
            with self.subTest(message=message):
                launches = Launches(self, reply, VERSION)
                with self.assertRaisesRegex(Failure, f"^{message}$"), \
                        contextlib.redirect_stdout(io.StringIO()):
                    start(launches)
                self.assertEqual((launches.launched, launches.closed), ([1], [1]))


class UnexpectedErrorTests(unittest.TestCase):
    def test_error_kinds_are_fixed_and_never_carry_error_text(self):
        tool = ["certutil", "sensitive argument"]
        for error, kind in [
            (subprocess.TimeoutExpired(tool, 5, output=b"sensitive"), "timed out"),
            (ConnectionResetError("sensitive"), "browser pipe lost"),
            (BrokenPipeError("sensitive"), "browser pipe lost"),
            (FileNotFoundError(2, "sensitive", "sensitive"), "required runner tool missing"),
            (subprocess.CalledProcessError(1, tool, stderr=b"sensitive"), "runner tool refused"),
            (KeyError("sensitive"), "browser harness failed"),
        ]:
            with self.subTest(kind=kind):
                self.assertEqual(unexpected(error, "runner trust store"),
                                 f"{kind} during runner trust store")
