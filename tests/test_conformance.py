from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from bridge_demo import ReferenceReceiver, sha256_bytes  # noqa: E402

EXPECTED = "231f6819dd40525827715ee0b893c1273b745a83a1f45a620c5aa6db40ddf4bb"
SESSION = "20000000-0000-4000-8000-000000000001"


def load(name: str):
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


class XiBridgeConformance(unittest.TestCase):
    def test_examples_share_protocol_and_session(self):
        for path in sorted((ROOT / "examples").glob("*.json")):
            obj = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(obj["protocol"], "xi.exchange.v1")
            self.assertEqual(obj["session_id"], SESSION)
            self.assertIn("message_id", obj)
            self.assertIn("sender", obj)
            self.assertIn("recipient", obj)

    def test_capsule_fixture_digest_and_size(self):
        data = (ROOT / "examples" / "sample-capsule.txt").read_bytes()
        offer = load("03-capsule-offer.json")
        content = offer["payload"]["capsule"]["content"]
        self.assertEqual(len(data), 48)
        self.assertEqual(sha256_bytes(data), EXPECTED)
        self.assertEqual(content["sha256"], EXPECTED)
        self.assertEqual(content["size_bytes"], len(data))
        self.assertEqual(content["data"].encode("utf-8"), data)

    def test_result_binds_request_and_artifact(self):
        req = load("05-tool-request.json")
        result = load("06-tool-result.json")
        receipt = result["payload"]["receipt"]
        self.assertEqual(result["request_id"], req["request_id"])
        self.assertEqual(receipt["request_id"], req["request_id"])
        self.assertEqual(receipt["operation"], req["payload"]["operation"])
        self.assertEqual(result["payload"]["output"]["sha256"], EXPECTED)
        self.assertEqual(receipt["artifact_sha256"], EXPECTED)

    def test_replay_does_not_execute_twice(self):
        request = load("05-tool-request.json")
        capsule = (ROOT / "examples" / "sample-capsule.txt").read_bytes()
        receiver = ReferenceReceiver()
        first = receiver.execute(request, capsule)
        second = receiver.execute(request, capsule)
        self.assertEqual(first, second)
        self.assertEqual(receiver.execution_counter, 1)
        self.assertEqual(first["receipt"]["execution_count"], 1)

    def test_runtime_receipt_uses_rfc3339_datetime(self):
        request = load("05-tool-request.json")
        capsule = (ROOT / "examples" / "sample-capsule.txt").read_bytes()
        receiver = ReferenceReceiver()
        result = receiver.execute(request, capsule)
        recorded_at = result["receipt"]["recorded_at"]
        parsed = datetime.fromisoformat(recorded_at.replace("Z", "+00:00"))
        self.assertIsNotNone(parsed.tzinfo)

    def test_unexposed_operation_is_denied(self):
        request = load("05-tool-request.json")
        request["request_id"] = "40000000-0000-4000-8000-000000000099"
        request["payload"]["operation"] = "shell.exec"
        receiver = ReferenceReceiver()
        result = receiver.execute(request, b"ignored")
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["receipt"]["execution_count"], 0)
        self.assertEqual(receiver.execution_counter, 0)

    def test_conflicting_replay_changed_capsule_id_is_denied(self):
        request = load("05-tool-request.json")
        capsule = (ROOT / "examples" / "sample-capsule.txt").read_bytes()
        receiver = ReferenceReceiver()
        receiver.execute(request, capsule)
        changed = json.loads(json.dumps(request))
        changed["payload"]["capsule_id"] = "different-capsule"
        result = receiver.execute(changed, capsule)
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["receipt"]["note"], "request_id_conflict")
        self.assertEqual(receiver.execution_counter, 1)

    def test_conflicting_replay_changed_full_input_is_denied(self):
        request = load("05-tool-request.json")
        capsule = (ROOT / "examples" / "sample-capsule.txt").read_bytes()
        receiver = ReferenceReceiver()
        receiver.execute(request, capsule)
        changed = json.loads(json.dumps(request))
        changed["payload"]["input"] = {"mode": "different"}
        result = receiver.execute(changed, capsule)
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["receipt"]["note"], "request_id_conflict")
        self.assertEqual(receiver.execution_counter, 1)

    def test_conflicting_replay_changed_capsule_bytes_is_denied(self):
        request = load("05-tool-request.json")
        capsule = (ROOT / "examples" / "sample-capsule.txt").read_bytes()
        receiver = ReferenceReceiver()
        receiver.execute(request, capsule)
        result = receiver.execute(request, capsule + b"tampered")
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["receipt"]["note"], "request_id_conflict")
        self.assertEqual(receiver.execution_counter, 1)


if __name__ == "__main__":
    unittest.main()
