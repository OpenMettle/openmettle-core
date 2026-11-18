"""Exercise the private pipe and failure reporting without starting Chrome."""
import contextlib
import io
import json
import socket
import subprocess
import unittest

from qualify import DevTools, Failure, Progress, journey, unexpected


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


class UnexpectedErrorTests(unittest.TestCase):
    def test_silent_browser_is_reported_by_the_phase_in_progress(self):
        client, peer = socket.socketpair()
        with client, peer:
            client.settimeout(0.05)
            progress = Progress()
            progress.enter("browser start")
            # The browser answers its version, then never answers again.
            peer.sendall(b'{"id":1,"result":{"product":"Chrome/1.2.3.4"}}\0')
            with self.assertRaises(TimeoutError) as raised, \
                    contextlib.redirect_stdout(io.StringIO()):
                journey(DevTools(client), "https://app.test", "https://issuer.test",
                        progress.enter)
            self.assertEqual(unexpected(raised.exception, progress.phase),
                             "timed out during browser target setup")

    def test_browser_that_never_answers_is_a_start_timeout(self):
        client, peer = socket.socketpair()
        with client, peer:
            client.settimeout(0.05)
            progress = Progress()
            progress.enter("browser start")
            with self.assertRaises(TimeoutError) as raised:
                journey(DevTools(client), "https://app.test", "https://issuer.test",
                        progress.enter)
            self.assertEqual(unexpected(raised.exception, progress.phase),
                             "timed out during browser start")

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
