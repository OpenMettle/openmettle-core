"""Exercise the private pipe and failure reporting without starting Chrome."""
import json
import socket
import unittest

from qualify import DevTools, Failure


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

    def test_page_exception_does_not_expose_exception_detail(self):
        client, peer = socket.socketpair()
        with client, peer:
            peer.sendall(b'{"id":1,"result":{"exceptionDetails":{"text":"sensitive"}}}\0')
            with self.assertRaisesRegex(Failure, "^page action failed$"):
                DevTools(client).evaluate("true")
