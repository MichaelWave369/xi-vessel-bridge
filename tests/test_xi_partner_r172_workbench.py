"""R17.2 candidate-only offline review and export redaction negative tests."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
import xi_capability_r171 as cap
import xi_pilot_r18 as pilot
import xi_partner_r172_workbench as intake


class IntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = json.loads((ROOT / "roadmap" / "capability-registry.json").read_text())

    def fake_response(self):
        return {
            "schema": cap.RESPONSE_SCHEMA,
            "reply_to_registry_sha256": cap.document_hash(self.reg),
            "statement": "FICTIONAL: never a Xi agreement",
            "records": [{
                "slot_id": "xi-preview-02", "name": "fictional test candidate",
                "operation": "example.read", "schema_sha256": "a" * 64,
                "endpoint_description": "this is not an endpoint",
                "evidence_url": "https://www.xi-field.com/#community",
                "source_author": "Synthetic test author"
            }]
        }

    def test_no_input_is_still_blocked(self):
        report = intake.review(self.reg)
        self.assertEqual(report["verdict"], "BLOCKED_PENDING_EXTERNAL_EVIDENCE")
        self.assertEqual(report["file_reviews"]["partner_response"]["state"], "NOT_SUPPLIED")
        self.assertEqual(len(report["unmapped_slots"]), 13)
        self.assertEqual(report["independently_verified_partner_capabilities"], 0)

    def test_candidate_response_marks_one_slot_only(self):
        report = intake.review(self.reg, response=self.fake_response())
        self.assertEqual(report["candidate_slots"], ["xi-preview-02"])
        self.assertEqual(len(report["unmapped_slots"]), 12)
        self.assertEqual(report["authorized_operations"], 0)

    def test_export_is_redacted(self):
        report = intake.review(self.reg, response=self.fake_response())
        redacted = json.dumps(report)
        for raw in ["example.read", "Synthetic test author", "this is not an endpoint",
                    "FICTIONAL: never a Xi agreement"]:
            self.assertNotIn(raw, redacted)
        self.assertIn("xi-preview-02", redacted)

    def test_pilot_pins_and_approval_flags_remain_self_reported(self):
        draft = pilot.draft()
        draft["phi_operator_approval"] = True
        draft["xi_peer_pin"] = "synthetic-claimed-key-not-verified"
        report = intake.review(self.reg, preflight=draft)
        self.assertEqual(report["file_reviews"]["pilot_preflight"]["unverified_candidate_claim_count"], 2)
        self.assertEqual(report["file_reviews"]["pilot_preflight"]["independent_proof_count"], 0)
        self.assertFalse(report["live_xi_connected"])

    def test_matching_transcript_still_not_real_execution(self):
        t = pilot.empty_transcript()
        t["status"] = "candidate_unverified"
        t["phi_observed_sha256"] = pilot.sha(pilot.PAYLOAD)
        t["xi_observed_sha256"] = pilot.sha(pilot.PAYLOAD)
        t["phi_receipt_reference"] = "fictional local"
        t["xi_receipt_reference"] = "fictional remote"
        t["two_physical_hosts_confirmed"] = True
        result = intake.review(self.reg, transcript=t)
        self.assertTrue(result["file_reviews"]["pilot_transcript"]["self_reported_digest_match"])
        self.assertEqual(result["file_reviews"]["pilot_transcript"]["independently_authenticated_receipts"], 0)

    def test_injected_authority_refused(self):
        payload = self.fake_response()
        payload["authority"] = "system-admin"
        with self.assertRaises(cap.Refused):
            intake.review(self.reg, response=payload)

    def test_changed_registry_digest_refused(self):
        payload = self.fake_response()
        payload["reply_to_registry_sha256"] = "0" * 64
        with self.assertRaises(cap.Refused):
            intake.review(self.reg, response=payload)

    def test_unsupported_public_urls_refused(self):
        payload = self.fake_response()
        payload["records"][0]["evidence_url"] = "http://evil.example/secret"
        with self.assertRaises(cap.Refused):
            intake.review(self.reg, response=payload)

    def test_live_preflight_claim_refused(self):
        preflight = pilot.draft()
        preflight["live_xi_connected"] = True
        with self.assertRaises(pilot.Refused):
            intake.review(self.reg, preflight=preflight)

    def test_input_file_size_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b"A" * (intake.MAX_INPUT + 1))
            with self.assertRaises(intake.Refused):
                intake.strict_read(path)

    def test_cli_no_file_deterministic_blocked(self):
        script = ROOT / "reference" / "python" / "xi_partner_r172_workbench.py"
        done = subprocess.run([sys.executable, str(script)],
                              capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["verdict"], "BLOCKED_PENDING_EXTERNAL_EVIDENCE")
        self.assertIn("registry", report["input_sha256"])

    def test_cli_combined_intake_and_byte_fingerprints(self):
        script = ROOT / "reference" / "python" / "xi_partner_r172_workbench.py"
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            files = {"response": self.fake_response(), "preflight": pilot.draft(),
                     "transcript": pilot.empty_transcript()}
            cmd = [sys.executable, str(script)]
            for name, payload in files.items():
                path = folder / (name + ".json")
                path.write_text(json.dumps(payload), encoding="utf-8")
                cmd.extend(["--" + name, str(path)])
            done = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["file_reviews"]["partner_response"]["candidate_count"], 1)
        self.assertEqual(len(report["input_sha256"]), 4)
        self.assertFalse(report["live_xi_connected"])

    def test_require_live_stays_refused_even_with_complete_shapes(self):
        script = ROOT / "reference" / "python" / "xi_partner_r172_workbench.py"
        done = subprocess.run([sys.executable, str(script), "--require-live"],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertIn("R17_2_REFUSED", done.stderr)

    def test_invalid_json_error_does_not_echo_secret(self):
        script = ROOT / "reference" / "python" / "xi_partner_r172_workbench.py"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.json"
            path.write_text('{"PRIVATE_TOKEN":"do-not-echo",', encoding="utf-8")
            done = subprocess.run([sys.executable, str(script), "--response", str(path)],
                                  capture_output=True, text=True)
        self.assertEqual(done.returncode, 1)
        self.assertNotIn("do-not-echo", done.stdout + done.stderr)
        self.assertIn("INVALID_INPUT_REFUSED", done.stdout)


if __name__ == "__main__":
    unittest.main()
