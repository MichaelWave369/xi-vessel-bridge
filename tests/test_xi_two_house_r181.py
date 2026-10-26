"""R18.1 two-house local Ed25519/synthetic-only protocol negative controls."""
import base64
import copy
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
import xi_two_house_r181 as r181
import phi_xi_r16_loopback as r16
import xi_pilot_r18 as r18
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TwoHouseSimulationTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.phi_key = Ed25519PrivateKey.generate()
        self.xi_key = Ed25519PrivateKey.generate()
        self.untrusted_key = Ed25519PrivateKey.generate()
        self.session = str(uuid.uuid4())
        self.now = 1_700_000_000
        self.phi = r181.House(self.root / "phi", self.phi_key,
                              r16.identity(self.xi_key), "phi-sim", self.session,
                              allow_digest=True)
        self.xi = r181.House(self.root / "xi", self.xi_key,
                             r16.identity(self.phi_key), "xi-sim", self.session,
                             allow_digest=True)

    def handshake(self):
        for server, client in ((self.phi, self.xi), (self.xi, self.phi)):
            challenge = server.challenge(now=self.now)
            proof = client.proof(challenge, now=self.now)
            receipt = server.accept_proof(proof, now=self.now)
            client.confirm(receipt, now=self.now)

    def exchange(self):
        self.handshake()
        packet = self.phi.make_request(now=self.now)
        answer = self.xi.accept_request(packet, now=self.now)
        return packet, answer

    def test_bilateral_handshake_and_receipt_confirmed(self):
        packet, answer = self.exchange()
        status = self.phi.accept_result(answer, now=self.now)
        self.assertEqual(status["status"], "LOCAL_SIGNED_SYNTHETIC_DIGEST_CONFIRMED")
        self.assertEqual(answer["payload"]["receipt"]["artifact_sha256"], r18.sha(r18.PAYLOAD))
        self.assertFalse(status["live_xi_connected"])

    def test_not_ready_unless_both_handshakes(self):
        with self.assertRaisesRegex(r181.Refused, "handshake"):
            self.phi.make_request(now=self.now)
        challenge = self.phi.challenge(now=self.now)
        proof = self.xi.proof(challenge, now=self.now)
        self.phi.accept_proof(proof, now=self.now)
        with self.assertRaisesRegex(r181.Refused, "handshake"):
            self.phi.make_request(now=self.now)

    def test_received_duplicate_request_rejected_even_after_restart(self):
        packet, _ = self.exchange()
        with self.assertRaises(Exception):
            self.xi.accept_request(packet, now=self.now)
        restarted = r181.House(self.root / "xi", self.xi_key,
                               r16.identity(self.phi_key), "xi-sim", self.session,
                               allow_digest=True)
        self.xi = restarted
        self.handshake()
        with self.assertRaises(Exception):
            self.xi.accept_request(packet, now=self.now)

    def test_result_receipt_cannot_be_replayed(self):
        _, answer = self.exchange()
        self.phi.accept_result(answer, now=self.now)
        with self.assertRaises(r181.Refused):
            self.phi.accept_result(answer, now=self.now)

    def test_signature_tampering_rejected(self):
        packet, _ = self.exchange()
        modified = copy.deepcopy(packet)
        modified["payload"]["operation"] = "repo.write"
        with self.assertRaises(r181.Refused):
            self.xi.accept_request(modified, now=self.now)

    def test_scope_broadening_refused_even_when_validly_signed(self):
        self.handshake()
        packet = r181.signed(self.phi_key, kind="tool.request", sender="phi-sim",
                             recipient=self.xi.me, session=self.session,
                             request_id=str(uuid.uuid4()),
                             payload={"operation": "repo.write", "permission_requested": "explicit_grant",
                                      "input": r18.fixture(), "dry_run": True}, now=self.now)
        with self.assertRaisesRegex(r181.Refused, "scope"):
            self.xi.accept_request(packet, now=self.now)

    def test_digest_requires_receiving_houses_own_opt_in(self):
        self.handshake()
        packet = self.phi.make_request(now=self.now)
        denied = r181.House(self.root / "xi", self.xi_key,
                            r16.identity(self.phi_key), "xi-sim", self.session,
                            allow_digest=False)
        self.xi = denied
        self.handshake()
        with self.assertRaisesRegex(r181.Refused, "permit"):
            self.xi.accept_request(packet, now=self.now)

    def test_invalid_payload_bytes_rejected(self):
        self.handshake()
        fixture = r18.fixture()
        fixture["sha256"] = "0" * 64
        packet = r181.signed(self.phi_key, kind="tool.request", sender="phi-sim",
                             recipient=self.xi.me, session=self.session,
                             request_id=str(uuid.uuid4()),
                             payload={"operation": r181.OPERATION,
                                      "permission_requested": "read_only",
                                      "input": fixture, "dry_run": True}, now=self.now)
        with self.assertRaises(r18.Refused):
            self.xi.accept_request(packet, now=self.now)

    def test_untrusted_key_cannot_impersonate_pinned_phi(self):
        self.handshake()
        packet = r181.signed(self.untrusted_key, kind="tool.request", sender="phi-sim",
                             recipient=self.xi.me, session=self.session,
                             request_id=str(uuid.uuid4()),
                             payload={"operation": r181.OPERATION,
                                      "permission_requested": "read_only",
                                      "input": r18.fixture(), "dry_run": True},
                             now=self.now)
        with self.assertRaises(r181.Refused):
            self.xi.accept_request(packet, now=self.now)

    def test_wrong_session_rejected(self):
        self.handshake()
        packet = r181.signed(self.phi_key, kind="tool.request", sender="phi-sim",
                             recipient=self.xi.me, session=str(uuid.uuid4()),
                             request_id=str(uuid.uuid4()),
                             payload={"operation": r181.OPERATION,
                                      "permission_requested": "read_only",
                                      "input": r18.fixture(), "dry_run": True},
                             now=self.now)
        with self.assertRaisesRegex(r181.Refused, "session"):
            self.xi.accept_request(packet, now=self.now)

    def test_wrong_recipient_rejected(self):
        self.handshake()
        packet = r181.signed(self.phi_key, kind="tool.request", sender="phi-sim",
                             recipient=r16.identity(self.untrusted_key), session=self.session,
                             request_id=str(uuid.uuid4()),
                             payload={"operation": r181.OPERATION,
                                      "permission_requested": "read_only",
                                      "input": r18.fixture(), "dry_run": True},
                             now=self.now)
        with self.assertRaises(r181.Refused):
            self.xi.accept_request(packet, now=self.now)

    def test_expired_signed_message_rejected(self):
        self.handshake()
        packet = self.phi.make_request(now=self.now)
        with self.assertRaisesRegex(r181.Refused, "expiry"):
            self.xi.accept_request(packet, now=self.now + r181.TTL + 1)

    def test_authority_injection_rejected(self):
        self.handshake()
        packet = self.phi.make_request(now=self.now)
        packet["authority"] = "admin"
        with self.assertRaises(r181.Refused):
            self.xi.accept_request(packet, now=self.now)

    def test_pause_denies_receiver_without_pausing_sender(self):
        self.handshake()
        packet = self.phi.make_request(now=self.now)
        (self.xi.state / "PAUSED").touch()
        with self.assertRaises(r16.Refused):
            self.xi.accept_request(packet, now=self.now)
        self.assertTrue(self.phi.ready() is None)

    def test_revocation_persists_in_receiver_ledger(self):
        self.handshake()
        packet = self.phi.make_request(now=self.now)
        self.xi.revoke()
        with self.assertRaises(r16.Refused):
            self.xi.accept_request(packet, now=self.now)
        restarted = r181.House(self.xi.state, self.xi_key, r16.identity(self.phi_key),
                               "xi-sim", self.session, allow_digest=True)
        with self.assertRaisesRegex(r16.Refused, "revoked"):
            restarted.challenge(now=self.now)

    def test_bad_result_signature_and_digest_rejected(self):
        packet, answer = self.exchange()
        changed = copy.deepcopy(answer)
        changed["payload"]["receipt"]["artifact_sha256"] = "0" * 64
        with self.assertRaises(r181.Refused):
            self.phi.accept_result(changed, now=self.now)
        self.phi.accept_result(answer, now=self.now)

    def test_signed_mismatched_receipt_request_digest_rejected(self):
        packet, answer = self.exchange()
        p = copy.deepcopy(answer["payload"])
        p["request_sha256"] = "0" * 64
        forged = r181.signed(self.xi_key, kind="tool.result", sender="xi-sim",
                              recipient=self.phi.me, session=self.session,
                              request_id=packet["request_id"], payload=p, now=self.now)
        with self.assertRaisesRegex(r181.Refused, "tampered"):
            self.phi.accept_result(forged, now=self.now)

    def test_conformance_envelope_shape_and_readonly_receipt(self):
        packet, answer = self.exchange()
        schema = json.loads((ROOT / "spec" / "xi.exchange.v1.schema.json").read_text())
        receipt_schema = json.loads((ROOT / "spec" / "receipt.schema.json").read_text())
        tool_schema = json.loads((ROOT / "spec" / "tool-request.schema.json").read_text())
        self.assertEqual(set(packet), r181.ENVELOPE)
        self.assertTrue(set(schema["required"]) <= set(packet))
        self.assertEqual(packet["type"], "tool.request")
        self.assertIn(packet["type"], schema["properties"]["type"]["enum"])
        self.assertEqual(set(packet["payload"]), set(tool_schema["required"]) | {"dry_run"})
        self.assertEqual(set(answer["payload"]["receipt"]), set(receipt_schema["required"]) | {"artifact_sha256"})
        self.assertEqual(answer["payload"]["receipt"]["execution_count"], 1)

    def test_worker_rpc_denies_unknown_commands(self):
        with self.assertRaises(r181.Refused):
            r181.handle(self.phi, {"command": "shell.exec", "command_string": "echo X"})
        with self.assertRaises(r181.Refused):
            r181.handle(self.phi, {"command": "make-request", "authority": "admin"})

    def test_demo_executes_real_separate_local_processes(self):
        data = r181.demo()
        self.assertEqual(data["process_count"], 2)
        self.assertEqual(data["physical_hosts"], 1)
        self.assertTrue(data["bidirectional_local_digest"])
        self.assertTrue(data["durable_request_replay_refused_after_restart"])
        self.assertEqual(data["status"], "R18_1_TWO_HOUSE_LOCAL_SIMULATION_PASS")
        self.assertFalse(data["live_xi_connected"])

    def test_cli_demo_and_require_live_refusal(self):
        script = ROOT / "reference" / "python" / "xi_two_house_r181.py"
        good = subprocess.run([sys.executable, str(script), "demo"],
                              capture_output=True, text=True, timeout=25)
        self.assertEqual(good.returncode, 0, good.stderr + good.stdout)
        self.assertEqual(json.loads(good.stdout)["physical_hosts"], 1)
        bad = subprocess.run([sys.executable, str(script), "require-live"],
                             capture_output=True, text=True)
        self.assertEqual(bad.returncode, 2)
        self.assertIn("R18_1_REFUSED", bad.stderr)


if __name__ == "__main__":
    unittest.main()
