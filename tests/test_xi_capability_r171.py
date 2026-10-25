"""R17.1 capability registry and partner reply negative controls; no network."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
import xi_capability_r171 as r171


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads((ROOT / "roadmap" / "capability-registry.json").read_text())

    def data(self):
        return copy.deepcopy(self.registry)

    def fail(self, doc):
        with self.assertRaises(r171.Refused):
            r171.validate_registry(doc)

    def test_baseline_registry_thirteen_unmapped_slots(self):
        reg = r171.validate_registry(self.data())
        self.assertEqual(len(reg["xi_slots"]), 13)
        self.assertEqual(sum(1 for s in reg["xi_slots"] if s["authorized"]), 0)
        self.assertFalse(reg["live_xi_connected"])

    def test_local_candidates_are_read_only_and_not_exposed(self):
        reg = r171.validate_registry(self.data())
        self.assertEqual(len(reg["phi_candidates"]), 3)
        self.assertTrue(all(c["read_only"] and not c["exposed_remotely"] for c in reg["phi_candidates"]))

    def test_refuse_invented_xi_capability(self):
        reg = self.data()
        reg["xi_slots"][0]["native_operation"] = "model.invoke"
        self.fail(reg)

    def test_refuse_pretend_authenticated_slot(self):
        reg = self.data()
        reg["xi_slots"][0]["independently_verified"] = True
        self.fail(reg)

    def test_refuse_auto_grants(self):
        reg = self.data()
        reg["auto_grants"] = True
        self.fail(reg)

    def test_refuse_remote_exposure(self):
        reg = self.data()
        reg["phi_candidates"][0]["exposed_remotely"] = True
        self.fail(reg)

    def test_refuse_duplicate_preview_slot(self):
        reg = self.data()
        reg["xi_slots"][1]["slot_id"] = reg["xi_slots"][0]["slot_id"]
        self.fail(reg)

    def test_refuse_renaming_local_candidate(self):
        reg = self.data()
        reg["phi_candidates"][0]["id"] = "phi.remote.shell"
        self.fail(reg)

    def test_request_is_untrusted_questionnaire_only(self):
        req = r171.make_request(self.data())
        self.assertEqual(req["registry_sha256"], r171.document_hash(self.data()))
        self.assertEqual(req["reply_contract"], r171.RESPONSE_SCHEMA)
        self.assertEqual(len(req["slots"]), 13)
        self.assertFalse(req["allow_credentials"])
        self.assertFalse(req["authorization_from_response"])

    def test_empty_response_still_unmapped(self):
        response = {
            "schema": r171.RESPONSE_SCHEMA, "reply_to_registry_sha256": r171.document_hash(self.data()),
            "records": [], "statement": "No response yet"
        }
        result = r171.validate_response(response, self.data())
        self.assertEqual(result["candidate_records"], 0)
        self.assertEqual(result["authorized"], 0)
        self.assertEqual(len(result["still_unmapped"]), 13)

    def test_candidate_response_not_promoted(self):
        response = {
            "schema": r171.RESPONSE_SCHEMA, "reply_to_registry_sha256": r171.document_hash(self.data()),
            "statement": "Self-reported candidate, requires independent verification",
            "records": [{
                "slot_id": "xi-preview-01", "name": "partner draft only",
                "operation": "candidate.read", "schema_sha256": "a" * 64,
                "endpoint_description": "No live URL supplied",
                "evidence_url": "https://www.xi-field.com/#community",
                "source_author": "Unverified submitter"
            }]
        }
        result = r171.validate_response(response, self.data())
        self.assertEqual(result["candidate_records"], 1)
        self.assertEqual(result["independently_verified"], 0)
        self.assertEqual(result["authorized"], 0)

    def test_response_cannot_inject_authority(self):
        response = {
            "schema": r171.RESPONSE_SCHEMA, "reply_to_registry_sha256": r171.document_hash(self.data()),
            "statement": "Test", "records": [], "grant": "admin"
        }
        with self.assertRaises(r171.Refused):
            r171.validate_response(response, self.data())

    def test_response_cannot_swap_registry_hash(self):
        response = {
            "schema": r171.RESPONSE_SCHEMA, "reply_to_registry_sha256": "0" * 64,
            "statement": "Test", "records": []
        }
        with self.assertRaises(r171.Refused):
            r171.validate_response(response, self.data())

    def test_response_cannot_name_duplicate_slot(self):
        record = {
            "slot_id": "xi-preview-01", "name": "test", "operation": "candidate.read",
            "schema_sha256": "0" * 64, "endpoint_description": "Local draft only",
            "evidence_url": "https://www.xi-field.com/#community", "source_author": "test"
        }
        response = {
            "schema": r171.RESPONSE_SCHEMA, "reply_to_registry_sha256": r171.document_hash(self.data()),
            "statement": "Test", "records": [record, record]
        }
        with self.assertRaises(r171.Refused):
            r171.validate_response(response, self.data())

    def test_response_refuses_file_url(self):
        record = {
            "slot_id": "xi-preview-01", "name": "test", "operation": "candidate.read",
            "schema_sha256": "0" * 64, "endpoint_description": "Local draft only",
            "evidence_url": "file:///etc/passwd", "source_author": "test"
        }
        response = {
            "schema": r171.RESPONSE_SCHEMA, "reply_to_registry_sha256": r171.document_hash(self.data()),
            "statement": "Test", "records": [record]
        }
        with self.assertRaises(r171.Refused):
            r171.validate_response(response, self.data())

    def test_cli_inspect_green(self):
        job = subprocess.run([sys.executable, str(ROOT / "reference" / "python" / "xi_capability_r171.py"),
                              "inspect"], capture_output=True, text=True)
        self.assertEqual(job.returncode, 0, job.stderr)
        self.assertEqual(json.loads(job.stdout)["mapped_xi_capabilities"], 0)

    def test_cli_require_live_fails_closed(self):
        job = subprocess.run([sys.executable, str(ROOT / "reference" / "python" / "xi_capability_r171.py"),
                              "require-live"], capture_output=True, text=True)
        self.assertEqual(job.returncode, 2)
        self.assertIn("REFUSED", job.stderr)


if __name__ == "__main__":
    unittest.main()
