"""R7 public witness pack: no secret export, independent public checks."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_peer_r3 import CrossingError, canonical
from xi_peer_r7_handoff import (
    KIT_VERSION, MAX_KIT_BYTES, build_kit, read_kit, verify_kit,
)

CLI = ROOT / "reference" / "python" / "xi_peer_r7_handoff.py"


class PublicWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kit = build_kit()

    def test_valid_kit_verifies_without_private_keys(self):
        report = verify_kit(self.kit)
        self.assertEqual(report["status"], "R7_PUBLIC_WITNESS_VERIFIED")
        self.assertEqual(report["public_signatures_verified"], 2)
        self.assertEqual(report["tampered_vectors_rejected"], 3)
        self.assertFalse(report["live_xi_connected"])
        self.assertFalse(report["decryption_checked_by_public_verifier"])

    def test_public_only_payload_and_keys(self):
        raw = canonical(self.kit).decode("utf-8")
        for excluded in ("sign_private_b64", "decrypt_private_b64",
                         "FORGECORE_API_KEY", "XI_TABLE_WEBHOOK_SECRET",
                         "mikey-tessera-25661.key", "Bearer "):
            with self.subTest(excluded=excluded):
                self.assertNotIn(excluded, raw)
        self.assertEqual(self.kit["peers"]["phi-fixture"].keys(),
                         {"sign_public_b64", "decrypt_public_b64"})
        self.assertTrue(self.kit["self_signed_fixture"])
        self.assertFalse(self.kit["live_xi_connected"])

    def test_signature_forgery_detected_on_offer_and_receipt(self):
        for field in ("offer_frame", "receipt_frame"):
            kit = copy.deepcopy(self.kit)
            kit[field]["signature"] = kit["negative_vectors"]["bad_offer_signature"]["signature"]
            with self.subTest(field=field), self.assertRaisesRegex(CrossingError, "public_signature_invalid"):
                verify_kit(kit)

    def test_changed_wire_bytes_cannot_keep_signature(self):
        for field in ("offer_frame", "receipt_frame"):
            kit = copy.deepcopy(self.kit)
            kit[field]["ciphertext"] = kit["negative_vectors"]["bad_offer_ciphertext"]["ciphertext"]
            if field == "offer_frame":
                kit[field]["ciphertext"] = kit["negative_vectors"]["bad_offer_ciphertext"]["ciphertext"]
            else:
                kit[field]["ciphertext"] = kit[field]["ciphertext"][:-4] + "AAAA"
            with self.subTest(field=field), self.assertRaises(CrossingError):
                verify_kit(kit)

    def test_changed_disclosed_payload_rejected(self):
        kit = copy.deepcopy(self.kit)
        kit["synthetic_offer"]["xi_text"] += " altered"
        with self.assertRaisesRegex(CrossingError, "xi_hash_mismatch"):
            verify_kit(kit)
        kit = copy.deepcopy(self.kit)
        kit["synthetic_offer"]["ast"]["systems"].append("attacker")
        with self.assertRaisesRegex(CrossingError, "offer_digest_mismatch"):
            verify_kit(kit)

    def test_disclosed_receipt_must_bind_exact_request(self):
        kit = copy.deepcopy(self.kit)
        kit["synthetic_receipt"]["in_reply_to"] = "00000000-0000-4000-8000-000000000001"
        kit["receipt_payload_sha256"] = hashlib.sha256(canonical(kit["synthetic_receipt"])).hexdigest()
        with self.assertRaisesRegex(CrossingError, "kit_unbound_receipt"):
            verify_kit(kit)

    def test_cannot_upgrade_fixture_status(self):
        for key, value in (("live_xi_connected", True),
                           ("self_signed_fixture", False),
                           ("kit_version", "xi.real.production.v1"),
                           ("scope", "real_bridge")):
            kit = copy.deepcopy(self.kit)
            kit[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(CrossingError, "kit_invalid_scope"):
                verify_kit(kit)

    def test_cannot_swap_peer_identity(self):
        kit = copy.deepcopy(self.kit)
        kit["peers"]["phi-fixture"]["sign_public_b64"] = (
            kit["peers"]["xi-fixture"]["sign_public_b64"])
        with self.assertRaisesRegex(CrossingError, "public_signature_invalid"):
            verify_kit(kit)

    def test_cannot_replace_negative_with_valid_vector(self):
        kit = copy.deepcopy(self.kit)
        kit["negative_vectors"]["bad_offer_signature"] = kit["offer_frame"]
        with self.assertRaisesRegex(CrossingError, "kit_invalid_negative_control"):
            verify_kit(kit)

    def test_undeclared_fields_and_missing_signatures(self):
        kit = copy.deepcopy(self.kit)
        kit["credential"] = "do-not-admit"
        with self.assertRaisesRegex(CrossingError, "kit_invalid_shape"):
            verify_kit(kit)
        kit = copy.deepcopy(self.kit)
        kit["offer_frame"].pop("signature")
        with self.assertRaisesRegex(CrossingError, "invalid_frame_shape"):
            verify_kit(kit)

    def test_export_verify_cli_roundtrip_across_processes(self):
        with tempfile.TemporaryDirectory(prefix="xi-r7-") as name:
            target = Path(name) / "public-handoff.json"
            export = subprocess.run([sys.executable, str(CLI), "export", "--out", str(target)],
                                    text=True, capture_output=True, timeout=20)
            self.assertEqual(export.returncode, 0, export.stderr[-500:])
            self.assertEqual(json.loads(export.stdout)["status"], "R7_PUBLIC_WITNESS_VERIFIED")
            self.assertLess(target.stat().st_size, MAX_KIT_BYTES)
            inspect = subprocess.run([sys.executable, str(CLI), "verify", "--file", str(target)],
                                     text=True, capture_output=True, timeout=20)
            self.assertEqual(inspect.returncode, 0, inspect.stderr[-500:])
            self.assertEqual(json.loads(inspect.stdout)["status"], "R7_PUBLIC_WITNESS_VERIFIED")
            # No accidental overwrites of an existing artifact.
            again = subprocess.run([sys.executable, str(CLI), "export", "--out", str(target)],
                                   text=True, capture_output=True, timeout=20)
            self.assertNotEqual(again.returncode, 0)

    def test_refuse_duplicate_json_keys_and_oversized_data(self):
        with tempfile.TemporaryDirectory(prefix="xi-r7-") as name:
            target = Path(name) / "bad.json"
            target.write_text('{"kit_version":"one","kit_version":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(CrossingError, "kit_invalid_json"):
                read_kit(str(target))
            target.write_bytes(b"x" * (MAX_KIT_BYTES + 1))
            with self.assertRaisesRegex(CrossingError, "kit_file_size_invalid"):
                read_kit(str(target))


if __name__ == "__main__":
    unittest.main()
