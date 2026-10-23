"""R1 staging contract tests. All events and replies are synthetic and local."""
from __future__ import annotations

import copy
import hashlib
import http.client
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from time import time
from uuid import uuid4
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_table_r1 import XiTableStagingBridge, make_handler, MAX_BYTES  # noqa: E402


SECRET = b"test-secret-32-bytes-minimum-please-keep-it-local"


def synthetic_event():
    return {
        "schema": "xi.table.mention.mock.v1",
        "event_id": str(uuid4()),
        "room_id": "local-staging-room",
        "message_id": str(uuid4()),
        "kind": "mention",
        "target_seat": "Phi",
        "sender": {"seat_id": "human-local", "display_name": "Test human"},
        "body": "Hi @Phi, local-only synthetic message",
    }


def encode(event):
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class XiTableR1Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name) / "events.sqlite3")
        self.now = int(time())
        self.bridge = XiTableStagingBridge(
            SECRET, self.db, allowed_room="local-staging-room", clock=lambda: self.now)

    def tearDown(self):
        self.bridge.store.close()
        self.temp.cleanup()

    def send(self, event, *, timestamp=None, signature=None, raw=None):
        raw = encode(event) if raw is None else raw
        ts = str(self.now if timestamp is None else timestamp)
        sig = signature if signature is not None else self.bridge.signed(raw, ts)
        return self.bridge.handle(raw, ts, sig)

    def test_first_signed_mention_is_mock_only_and_receipted(self):
        event = synthetic_event()
        status, payload = self.send(event)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "mock_completed")
        self.assertEqual(payload["reply"]["mode"], "mock_only")
        self.assertEqual(payload["reply"]["reply_to"], event["message_id"])
        self.assertEqual(payload["receipt"]["event_sha256"], hashlib.sha256(encode(event)).hexdigest())
        self.assertNotIn(event["body"], json.dumps(payload))
        self.assertEqual(self.bridge.store.count(), 1)

    def test_duplicate_does_not_repeat_mock_invocation(self):
        event = synthetic_event()
        _, first = self.send(event)
        status, second = self.send(event)
        self.assertEqual(status, 200)
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(second["result"], first)
        self.assertEqual(self.bridge.store.count(), 1)

    def test_replay_survives_restart(self):
        event = synthetic_event()
        _, first = self.send(event)
        self.bridge.store.close()
        self.bridge = XiTableStagingBridge(
            SECRET, self.db, allowed_room="local-staging-room", clock=lambda: self.now)
        _, second = self.send(event)
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(second["result"], first)

    def test_same_event_id_changed_body_is_conflict(self):
        event = synthetic_event()
        self.send(event)
        other = copy.deepcopy(event)
        other["body"] = "Changed under same event ID"
        status, result = self.send(other)
        self.assertEqual(status, 409)
        self.assertEqual(result["reason"], "event_id_conflict")
        self.assertEqual(self.bridge.store.count(), 1)

    def test_bad_signature_is_denied_before_reservation(self):
        status, result = self.send(synthetic_event(), signature="sha256=" + "0" * 64)
        self.assertEqual(status, 401)
        self.assertEqual(result["reason"], "invalid_signature")
        self.assertEqual(self.bridge.store.count(), 0)

    def test_expired_timestamp_is_denied(self):
        status, result = self.send(synthetic_event(), timestamp=self.now - 301)
        self.assertEqual(status, 401)
        self.assertEqual(result["reason"], "expired_timestamp")
        self.assertEqual(self.bridge.store.count(), 0)

    def test_unaddressed_message_is_ignored(self):
        event = synthetic_event()
        event["target_seat"] = "Astra"
        status, payload = self.send(event)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ignored")
        self.assertEqual(self.bridge.store.count(), 0)

    def test_wrong_room_fails_closed(self):
        event = synthetic_event()
        event["room_id"] = "another-room"
        status, result = self.send(event)
        self.assertEqual(status, 403)
        self.assertEqual(result["reason"], "room_not_allowed")

    def test_private_context_fields_are_refused(self):
        event = synthetic_event()
        event["room_history"] = [{"role": "user", "content": "private"}]
        status, result = self.send(event)
        self.assertEqual(status, 422)
        self.assertEqual(result["reason"], "invalid_event_shape")
        self.assertEqual(self.bridge.store.count(), 0)

    def test_arbitrary_tool_command_is_refused(self):
        event = synthetic_event()
        event["operation"] = "shell.exec"
        status, result = self.send(event)
        self.assertEqual(status, 422)
        self.assertEqual(result["reason"], "invalid_event_shape")

    def test_non_json_and_oversize_rejected(self):
        raw = b"{oops}"
        status, result = self.send(synthetic_event(), raw=raw)
        self.assertEqual((status, result["reason"]), (422, "invalid_json"))
        raw = b"x" * (MAX_BYTES + 1)
        status, result = self.send(synthetic_event(), raw=raw)
        self.assertEqual((status, result["reason"]), (413, "invalid_body_size"))

    def test_pending_event_never_reexecutes_automatically(self):
        event = synthetic_event()
        raw = encode(event)
        state, _ = self.bridge.store.reserve(event["event_id"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(state, "new")
        status, result = self.send(event)
        self.assertEqual(status, 202)
        self.assertEqual(result["status"], "in_progress")

    def test_short_secret_refused(self):
        with self.assertRaises(ValueError):
            XiTableStagingBridge(b"short", ":memory:")

    def test_http_receiver_exposes_only_expected_routes(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.bridge))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            event = synthetic_event()
            raw = encode(event)
            headers = {
                "Content-Type": "application/json",
                "X-Xi-Timestamp": str(self.now),
                "X-Xi-Signature": self.bridge.signed(raw, str(self.now)),
            }
            conn.request("POST", "/v1/xi/events", raw, headers)
            result = conn.getresponse()
            self.assertEqual(result.status, 200)
            self.assertEqual(json.loads(result.read())["status"], "mock_completed")
            conn.request("POST", "/not-allowed", raw, headers)
            result = conn.getresponse()
            self.assertEqual(result.status, 404)
            result.read()
            conn.request("GET", "/healthz")
            result = conn.getresponse()
            self.assertEqual(result.status, 200)
            self.assertFalse(json.loads(result.read())["live_connection"])
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
