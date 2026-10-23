"""R9 independent nonce challenge and explicit signing-key pin checks.

All peers are SYNTHETIC and issue fixture credentials in their own runtime.
No real Xi/ForgeCore identity or network connection is claimed.
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_peer_r3 import CrossingError
from xi_peer_r9_challenge import (
    ChallengeLedger, create_challenge, create_response,
    read_json, sha256, validate_challenge, validate_pins, verify_response,
)

CLI = ROOT / "reference" / "python" / "xi_peer_r9_challenge.py"
NOW = int(time.time())


class R9ChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge = create_challenge(now=NOW)
        cls.response, cls.pins = create_response(cls.challenge, now=NOW)

    def test_happy_challenge_requires_separate_external_pins(self):
        result = verify_response(self.response, self.challenge, self.pins, now=NOW)
        self.assertEqual(result["status"], "R9_EXTERNAL_PIN_CHALLENGE_VERIFIED")
        self.assertEqual(result["challenge_bound_signatures"], 2)
        self.assertEqual(result["signers_against_external_pins"], 2)
        self.assertFalse(result["live_xi_connected"])

    def test_response_alone_cannot_set_trust_anchor(self):
        with self.assertRaisesRegex(CrossingError, "pins_invalid"):
            verify_response(self.response, self.challenge, {}, now=NOW)
        self.assertEqual(set(self.response), {
            "format", "challenge_sha256", "r8_witness", "attestations",
        })
        self.assertNotIn("trusted_pins", self.response)

    def test_wrong_pinned_signer_does_not_pass_even_with_valid_self_signed_witness(self):
        another_response, other_pins = create_response(self.challenge, now=NOW)
        with self.assertRaisesRegex(CrossingError, "external_pin_mismatch"):
            verify_response(another_response, self.challenge, self.pins, now=NOW)
        self.assertEqual(verify_response(another_response, self.challenge, other_pins, now=NOW)["status"],
                         "R9_EXTERNAL_PIN_CHALLENGE_VERIFIED")

    def test_swapped_pins_denied(self):
        pins = copy.deepcopy(self.pins)
        pins["peers"]["phi-fixture"], pins["peers"]["xi-fixture"] = (
            pins["peers"]["xi-fixture"], pins["peers"]["phi-fixture"])
        with self.assertRaisesRegex(CrossingError, "external_pin_mismatch"):
            verify_response(self.response, self.challenge, pins, now=NOW)

    def test_another_verifier_challenge_denied(self):
        other = create_challenge(now=NOW)
        with self.assertRaisesRegex(CrossingError, "response_wrong_challenge"):
            verify_response(self.response, other, self.pins, now=NOW)

    def test_recomputed_plaintext_hashes_do_not_fool_challenge(self):
        tampered = copy.deepcopy(self.response)
        tampered["r8_witness"]["r7_witness"]["synthetic_offer"]["ast"]["systems"].append("forged")
        with self.assertRaises(CrossingError):
            verify_response(tampered, self.challenge, self.pins, now=NOW)

    def test_forged_attestation_or_unbound_statement_fails(self):
        for key in ("phi-fixture", "xi-fixture"):
            bad = copy.deepcopy(self.response)
            bad["attestations"][key]["signature_b64"] = bad["attestations"][
                "xi-fixture" if key == "phi-fixture" else "phi-fixture"]["signature_b64"]
            with self.subTest(signer=key), self.assertRaisesRegex(CrossingError, "attestation_signature_invalid"):
                verify_response(bad, self.challenge, self.pins, now=NOW)
        bad = copy.deepcopy(self.response)
        bad["attestations"]["phi-fixture"]["statement"]["r7_witness_sha256"] = "0" * 64
        with self.assertRaisesRegex(CrossingError, "attestation_unbound"):
            verify_response(bad, self.challenge, self.pins, now=NOW)

    def test_unknown_peers_or_expanded_claims_denied(self):
        bad = copy.deepcopy(self.pins)
        bad["peers"]["unknown-fixture"] = bad["peers"]["phi-fixture"]
        with self.assertRaisesRegex(CrossingError, "pins_invalid"):
            verify_response(self.response, self.challenge, bad, now=NOW)
        bad = copy.deepcopy(self.response)
        bad["live_xi_connected"] = True
        with self.assertRaisesRegex(CrossingError, "response_invalid_shape"):
            verify_response(bad, self.challenge, self.pins, now=NOW)

    def test_expired_future_and_oversized_challenges_refused(self):
        expired = copy.deepcopy(self.challenge)
        with self.assertRaisesRegex(CrossingError, "challenge_expired_or_future"):
            validate_challenge(expired, now=expired["expires_at"])
        future = copy.deepcopy(self.challenge)
        with self.assertRaisesRegex(CrossingError, "challenge_expired_or_future"):
            validate_challenge(future, now=future["issued_at"] - 31)
        huge = copy.deepcopy(self.challenge)
        huge["expires_at"] = huge["issued_at"] + 301
        with self.assertRaisesRegex(CrossingError, "challenge_invalid"):
            validate_challenge(huge, now=NOW)

    def test_same_challenge_replay_and_changed_response_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "challenge-ledger.sqlite3")
            ledger = ChallengeLedger(path)
            ledger.record_once(self.challenge, self.response, now=NOW)
            with self.assertRaisesRegex(CrossingError, "challenge_replayed"):
                ledger.record_once(self.challenge, self.response, now=NOW)
            second, _ = create_response(self.challenge, now=NOW)
            with self.assertRaisesRegex(CrossingError, "challenge_conflict"):
                ledger.record_once(self.challenge, second, now=NOW)
            ledger.close()
            reopened = ChallengeLedger(path)
            try:
                with self.assertRaisesRegex(CrossingError, "challenge_replayed"):
                    reopened.record_once(self.challenge, self.response, now=NOW)
            finally:
                reopened.close()

    def test_public_response_has_no_long_term_private_identity_keys(self):
        raw = json.dumps(self.response)
        for forbidden in ("sign_private_b64", "decrypt_private_b64", "XI_TABLE_WEBHOOK_SECRET",
                          "FORGECORE_API_KEY", "Bearer ", "mikey-tessera-25661.key"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, raw)
        self.assertTrue(self.response["r8_witness"]["confidentiality_disclosed"])
        self.assertFalse(self.response["r8_witness"]["live_xi_connected"])

    def test_independent_cli_commands_and_replay_denial(self):
        with tempfile.TemporaryDirectory(prefix="xi-r9-") as directory:
            root = Path(directory)
            challenge, response, pins, ledger = [
                root / name for name in ("challenge.json", "response.json", "pins.json", "ledger.sqlite3")]
            def run(*args):
                return subprocess.run([sys.executable, str(CLI), *args],
                                      capture_output=True, text=True, timeout=25)
            issued = run("challenge", "--out", str(challenge))
            self.assertEqual(issued.returncode, 0, issued.stderr[-1000:])
            created = run("respond", "--challenge", str(challenge), "--out", str(response),
                          "--pins-out", str(pins))
            self.assertEqual(created.returncode, 0, created.stderr[-1000:])
            finished = run("verify", "--challenge", str(challenge), "--response", str(response),
                           "--pins", str(pins), "--ledger", str(ledger))
            self.assertEqual(finished.returncode, 0, finished.stderr[-1000:])
            self.assertEqual(json.loads(finished.stdout)["status"], "R9_EXTERNAL_PIN_CHALLENGE_VERIFIED")
            repeated = run("verify", "--challenge", str(challenge), "--response", str(response),
                           "--pins", str(pins), "--ledger", str(ledger))
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("challenge_replayed", repeated.stderr)
            self.assertEqual(set(read_json(str(pins))), {"format", "source", "peers"})


if __name__ == "__main__":
    unittest.main()
