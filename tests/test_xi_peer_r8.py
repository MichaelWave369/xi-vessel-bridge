"""R8 proves ciphertext -> disclosed sample bytes; R7 alone did not."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_peer_r3 import CrossingError, canonical
from xi_peer_r7_handoff import digest, verify_kit as verify_r7
from xi_peer_r8_disclosed import build_kit, read_kit, verify_kit

CLI = ROOT / "reference" / "python" / "xi_peer_r8_disclosed.py"


class R8PublicWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kit = build_kit()

    def test_independent_aead_decryption_matches_both_disclosed_payloads(self):
        report = verify_kit(self.kit)
        self.assertEqual(report["status"], "R8_PUBLIC_PLAINTEXT_BINDING_VERIFIED")
        self.assertEqual(report["sealed_frames_decrypted_and_compared"], 2)
        self.assertTrue(report["confidentiality_disclosed"])
        self.assertFalse(report["native_xi_parser_checked"])
        self.assertFalse(report["live_xi_connected"])

    def test_demonstrate_exact_gap_in_old_r7_then_r8_rejects(self):
        forged = copy.deepcopy(self.kit)
        witness = forged["r7_witness"]
        witness["synthetic_offer"]["ast"]["systems"].append("pretend-code-executed")
        witness["offer_payload_sha256"] = digest(witness["synthetic_offer"])
        # R7 linked the receipt to its unencrypted declared digest, not the
        # encrypted frame's ACTUAL plaintext. Repair these detached values.
        witness["synthetic_receipt"]["offered_payload_sha256"] = witness["offer_payload_sha256"]
        witness["receipt_payload_sha256"] = digest(witness["synthetic_receipt"])
        self.assertEqual(verify_r7(witness)["status"], "R7_PUBLIC_WITNESS_VERIFIED")
        with self.assertRaisesRegex(CrossingError, "disclosed_payload_does_not_match_ciphertext"):
            verify_kit(forged)

    def test_wrong_one_message_disclosure_key_fails_aead(self):
        altered = copy.deepcopy(self.kit)
        altered["one_message_content_keys"]["offer_aesgcm_key_b64"] = (
            altered["one_message_content_keys"]["receipt_aesgcm_key_b64"])
        with self.assertRaisesRegex(CrossingError, "public_disclosure_aead_invalid"):
            verify_kit(altered)

    def test_changed_signed_header_or_ciphertext_fails_signature(self):
        for key in ("nonce", "ciphertext", "request_id"):
            altered = copy.deepcopy(self.kit)
            if key == "request_id":
                altered["r7_witness"]["offer_frame"][key] = "00000000-0000-4000-8000-000000000000"
            else:
                altered["r7_witness"]["offer_frame"][key] = "AAAA"
            with self.subTest(field=key), self.assertRaises(CrossingError):
                verify_kit(altered)

    def test_reject_changed_receipt_with_recomputed_detached_hash(self):
        forged = copy.deepcopy(self.kit)
        w = forged["r7_witness"]
        w["synthetic_receipt"]["decision"] = "fixture_verified"
        w["synthetic_receipt"]["offered_payload_sha256"] = "0" * 64
        w["receipt_payload_sha256"] = digest(w["synthetic_receipt"])
        with self.assertRaises(CrossingError):
            verify_kit(forged)

    def test_disclosure_is_only_symmetric_frame_keys_never_identity_private(self):
        raw = canonical(self.kit).decode("utf-8")
        self.assertEqual(set(self.kit["one_message_content_keys"]),
                         {"offer_aesgcm_key_b64", "receipt_aesgcm_key_b64"})
        for disallowed in ("sign_private_b64", "decrypt_private_b64", "FORGECORE_API_KEY",
                           "XI_TABLE_WEBHOOK_SECRET", "mikey-tessera-25661.key", "Bearer "):
            with self.subTest(pattern=disallowed):
                self.assertNotIn(disallowed, raw)
        self.assertTrue(self.kit["confidentiality_disclosed"])
        self.assertFalse(self.kit["live_xi_connected"])

    def test_flag_and_unknown_field_enforced(self):
        for key, value in [
            ("synthetic_only", False),
            ("live_xi_connected", True),
            ("confidentiality_disclosed", False),
            ("format", "Xi.TESSERA.v4"),
        ]:
            changed = copy.deepcopy(self.kit)
            changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(CrossingError, "r8_invalid_scope"):
                verify_kit(changed)
        changed = copy.deepcopy(self.kit)
        changed["user_private_history"] = "no"
        with self.assertRaisesRegex(CrossingError, "r8_invalid_shape"):
            verify_kit(changed)

    def test_missing_or_corrupted_disclosed_content_key_fails(self):
        changed = copy.deepcopy(self.kit)
        changed["one_message_content_keys"].pop("receipt_aesgcm_key_b64")
        with self.assertRaisesRegex(CrossingError, "r8_invalid_key_disclosure"):
            verify_kit(changed)
        changed = copy.deepcopy(self.kit)
        changed["one_message_content_keys"]["receipt_aesgcm_key_b64"] = "abc"
        with self.assertRaises(CrossingError):
            verify_kit(changed)

    def test_cli_export_verify_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="xi-r8-") as base:
            path = Path(base) / "disclosed-fixture.json"
            created = subprocess.run([sys.executable, str(CLI), "export", "--out", str(path)],
                                     capture_output=True, text=True, timeout=20)
            self.assertEqual(created.returncode, 0, created.stderr[-1000:])
            self.assertEqual(json.loads(created.stdout)["status"], "R8_PUBLIC_PLAINTEXT_BINDING_VERIFIED")
            loaded = read_kit(str(path))
            self.assertEqual(verify_kit(loaded)["sealed_frames_decrypted_and_compared"], 2)
            checked = subprocess.run([sys.executable, str(CLI), "verify", "--file", str(path)],
                                     capture_output=True, text=True, timeout=20)
            self.assertEqual(checked.returncode, 0, checked.stderr[-1000:])
            second = subprocess.run([sys.executable, str(CLI), "export", "--out", str(path)],
                                    capture_output=True, text=True, timeout=20)
            self.assertNotEqual(second.returncode, 0)

    def test_duplicate_json_keys_and_size_cap(self):
        with tempfile.TemporaryDirectory(prefix="xi-r8-") as base:
            path = Path(base) / "witness.json"
            path.write_text('{"format":"a","format":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(CrossingError, "r8_invalid_json"):
                read_kit(str(path))
            path.write_bytes(b"z" * 100_001)
            with self.assertRaisesRegex(CrossingError, "r8_file_size_invalid"):
                read_kit(str(path))


if __name__ == "__main__":
    unittest.main()
