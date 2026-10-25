"""R16 mutually pinned, durable replay, pause/revoke negative controls."""
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reference" / "python"))
import phi_xi_r16_loopback as r16

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class R16Tests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.state = Path(self.work.name)
        self.server = Ed25519PrivateKey.generate()
        self.client = Ed25519PrivateKey.generate()
        self.attacker = Ed25519PrivateKey.generate()
        self.gate = r16.Gate(self.state, self.server, r16.identity(self.client), "fixture")
        self.now = 1_700_000_000

    def exchange(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        proof = r16.make_proof(challenge, self.client, r16.identity(self.server), "fixture", now=self.now)
        receipt = self.gate.prove(proof, now=self.now)
        r16.verify_receipt(receipt, proof, r16.identity(self.server), "fixture", now=self.now)
        return challenge, proof, receipt

    def test_mutually_signed_receipt(self):
        challenge, proof, receipt = self.exchange()
        self.assertEqual(challenge["scope"], r16.SCOPE)
        self.assertEqual(receipt["status"], "fixture-accepted")
        self.assertEqual(receipt["proof_sha256"], r16.sha256(r16.canonical(proof)))

    def test_durable_replay_refused_after_gate_restart(self):
        _, proof, _ = self.exchange()
        restarted = r16.Gate(self.state, self.server, r16.identity(self.client), "fixture")
        with self.assertRaisesRegex(r16.Refused, "replay"):
            restarted.prove(proof, now=self.now)

    def test_revocation_persists_after_restart(self):
        self.gate.revoke()
        restarted = r16.Gate(self.state, self.server, r16.identity(self.client), "fixture")
        with self.assertRaisesRegex(r16.Refused, "revoked"):
            restarted.challenge(r16.identity(self.client), now=self.now)

    def test_pause_rejects_challenge_and_proof(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        proof = r16.make_proof(challenge, self.client, r16.identity(self.server), "fixture", now=self.now)
        (self.state / "PAUSED").touch()
        with self.assertRaisesRegex(r16.Refused, "paused"):
            self.gate.challenge(r16.identity(self.client), now=self.now)
        with self.assertRaisesRegex(r16.Refused, "paused"):
            self.gate.prove(proof, now=self.now)

    def test_unknown_identity_denied(self):
        with self.assertRaises(r16.Refused):
            self.gate.challenge(r16.identity(self.attacker), now=self.now)

    def test_wrong_client_signature_denied(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        attacker_proof = r16.sign(self.attacker, "prove", id=challenge["id"],
                                  to=r16.identity(self.server), room="fixture",
                                  scope=r16.SCOPE, nonce=challenge["nonce"],
                                  client_nonce="invalid-client-identity", ts=self.now)
        with self.assertRaises(r16.Refused):
            self.gate.prove(attacker_proof, now=self.now)

    def test_wrong_server_challenge_signature_denied(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        challenge["sig"] = base64.b64encode(b"b" * 64).decode()
        with self.assertRaisesRegex(r16.Refused, "signature"):
            r16.make_proof(challenge, self.client, r16.identity(self.server), "fixture", now=self.now)

    def test_tampered_challenge_nonce_denied(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        challenge["nonce"] = "a" * 40
        with self.assertRaises(r16.Refused):
            r16.make_proof(challenge, self.client, r16.identity(self.server), "fixture", now=self.now)

    def test_proof_wrong_room_denied(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        proof = r16.make_proof(challenge, self.client, r16.identity(self.server), "fixture", now=self.now)
        forged = r16.sign(self.client, "prove", id=proof["id"], to=proof["to"],
                          room="other", scope=r16.SCOPE, nonce=proof["nonce"],
                          client_nonce=proof["client_nonce"], ts=self.now)
        with self.assertRaises(r16.Refused):
            self.gate.prove(forged, now=self.now)

    def test_expired_challenge_denied(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        proof = r16.make_proof(challenge, self.client, r16.identity(self.server), "fixture", now=self.now)
        with self.assertRaises(r16.Refused):
            self.gate.prove(proof, now=self.now + r16.TTL + 1)

    def test_extra_field_rejected(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        challenge["authority"] = "admin"
        with self.assertRaises(r16.Refused):
            r16.make_proof(challenge, self.client, r16.identity(self.server), "fixture", now=self.now)

    def test_receipt_mutation_rejected(self):
        _, proof, receipt = self.exchange()
        receipt["status"] = "live_connected"
        with self.assertRaises(r16.Refused):
            r16.verify_receipt(receipt, proof, r16.identity(self.server), "fixture", now=self.now)

    def test_wrong_recipient_denied(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        altered = r16.sign(self.server, "challenge", id=challenge["id"], to=r16.identity(self.attacker),
                           room="fixture", scope=r16.SCOPE, nonce=challenge["nonce"],
                           ts=self.now, expires=self.now + r16.TTL)
        with self.assertRaises(r16.Refused):
            r16.make_proof(altered, self.client, r16.identity(self.server), "fixture", now=self.now)

    def test_future_or_stale_proof_rejected(self):
        challenge = self.gate.challenge(r16.identity(self.client), now=self.now)
        proof = r16.make_proof(challenge, self.client, r16.identity(self.server), "fixture", now=self.now)
        future = r16.sign(self.client, "prove", id=proof["id"], to=proof["to"],
                          room="fixture", scope=r16.SCOPE, nonce=proof["nonce"],
                          client_nonce=proof["client_nonce"], ts=self.now + 100)
        with self.assertRaises(r16.Refused):
            self.gate.prove(future, now=self.now)

    def test_refuse_nonloopback_bind(self):
        args = type("Options", (), {"host": "0.0.0.0", "state": self.state, "room": "fixture",
                                    "key": self.state / "unused", "peer": r16.identity(self.client)})()
        with self.assertRaisesRegex(r16.Refused, "non-loopback"):
            r16.serve(args)

    def test_bad_room_is_rejected(self):
        with self.assertRaises(r16.Refused):
            r16.Gate(self.state / "other", self.server, r16.identity(self.client), "../escape")

    def test_nonprivate_key_rejected(self):
        path = self.state / "private.raw"
        path.write_bytes(b"x" * 32)
        path.chmod(0o644)
        if sys.platform != "win32":
            with self.assertRaises(r16.Refused):
                r16.load_private(path)

    def test_two_process_demo_includes_restart_pause_and_revoke(self):
        result = r16.demo()
        self.assertEqual(result["status"], "R16_LOCAL_FIXTURE_PASS")
        self.assertTrue(result["replay_refused_after_restart"])
        self.assertFalse(result["live_xi_connected"])


if __name__ == "__main__":
    unittest.main()
