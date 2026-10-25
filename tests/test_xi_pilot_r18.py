"""R18 synthetic-only preflight and transcript safety tests."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
import xi_pilot_r18 as r18


class PilotTests(unittest.TestCase):
    def fail(self, fn, doc):
        with self.assertRaises(r18.Refused):
            fn(doc)

    def test_known_synthetic_payload(self):
        result = r18.verify_fixture(r18.fixture())
        self.assertEqual(result["sha256"], r18.sha(r18.PAYLOAD))
        self.assertFalse(result["live_xi_connected"])

    def test_fixture_bytes_tampering_refused(self):
        doc = r18.fixture()
        doc["payload_b64"] = doc["payload_b64"][:-4] + "AAAA"
        self.fail(r18.verify_fixture, doc)

    def test_fixture_hash_tampering_refused(self):
        doc = r18.fixture()
        doc["sha256"] = "0" * 64
        self.fail(r18.verify_fixture, doc)

    def test_fixture_omitting_provenance_refused(self):
        doc = r18.fixture()
        del doc["origin"]
        self.fail(r18.verify_fixture, doc)

    def test_fixture_grant_injection_refused(self):
        doc = r18.fixture()
        doc["remote_grant"] = "all"
        self.fail(r18.verify_fixture, doc)

    def test_pilot_draft_remains_blocked(self):
        result = r18.inspect_preflight(r18.draft())
        self.assertEqual(result["pilot_status"], "BLOCKED_PENDING_INDEPENDENT_PROOF")
        self.assertEqual(len(result["missing_claims"]), 10)
        self.assertEqual(result["independently_verified_gates"], 0)

    def test_signed_off_claims_remain_unverified(self):
        doc = r18.draft()
        doc["xi_peer_pin"] = "claimed-peer-key"
        doc["phi_operator_approval"] = True
        result = r18.inspect_preflight(doc)
        self.assertEqual(len(result["self_reported_unverified_claims"]), 2)
        self.assertEqual(result["independently_verified_gates"], 0)
        self.assertEqual(result["pilot_status"], "BLOCKED_PENDING_INDEPENDENT_PROOF")

    def test_unsafe_transport_declaration_refused(self):
        doc = r18.draft()
        doc["transport"] = "http://0.0.0.0:8080"
        self.fail(r18.inspect_preflight, doc)

    def test_live_claim_refused(self):
        doc = r18.draft()
        doc["live_xi_connected"] = True
        self.fail(r18.inspect_preflight, doc)

    def test_false_authority_refused(self):
        doc = r18.draft()
        doc["authority"] = "admin"
        self.fail(r18.inspect_preflight, doc)

    def test_scope_broadening_refused(self):
        doc = r18.draft()
        doc["scope"] = "repo.write"
        self.fail(r18.inspect_preflight, doc)

    def test_real_data_broadening_refused(self):
        doc = r18.draft()
        doc["data_classification"] = "private_phios_memory"
        self.fail(r18.inspect_preflight, doc)

    def test_operator_approval_must_be_boolean(self):
        doc = r18.draft()
        doc["xi_operator_approval"] = "true"
        self.fail(r18.inspect_preflight, doc)

    def test_not_run_transcript_is_honest(self):
        self.assertEqual(r18.inspect_transcript(r18.empty_transcript())["status"], "NOT_RUN")

    def test_not_run_cannot_claim_host_verified(self):
        doc = r18.empty_transcript()
        doc["two_physical_hosts_confirmed"] = True
        self.fail(r18.inspect_transcript, doc)

    def test_candidate_transcript_match_not_independent_proof(self):
        doc = r18.empty_transcript()
        doc["status"] = "candidate_unverified"
        doc["phi_observed_sha256"] = r18.sha(r18.PAYLOAD)
        doc["xi_observed_sha256"] = r18.sha(r18.PAYLOAD)
        doc["two_physical_hosts_confirmed"] = True
        doc["phi_receipt_reference"] = "self-reported"
        doc["xi_receipt_reference"] = "self-reported"
        result = r18.inspect_transcript(doc)
        self.assertTrue(result["self_reported_digest_match"])
        self.assertEqual(result["independently_authenticated_receipts"], 0)
        self.assertFalse(result["two_host_connection_verified"])

    def test_invalid_transcript_digest_refused(self):
        doc = r18.empty_transcript()
        doc["status"] = "candidate_unverified"
        doc["xi_observed_sha256"] = "not-a-hash"
        self.fail(r18.inspect_transcript, doc)

    def test_fixture_cli_round_trip(self):
        tool = [sys.executable, str(ROOT / "reference" / "python" / "xi_pilot_r18.py")]
        created = subprocess.run(tool + ["fixture"], capture_output=True, text=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        with tempfile.TemporaryDirectory() as temp:
            filename = Path(temp) / "fixture.json"
            filename.write_text(created.stdout, encoding="utf-8")
            checked = subprocess.run(tool + ["verify-fixture", "--file", str(filename)],
                                     capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["status"], "OFFLINE_SYNTHETIC_FIXTURE_VERIFIED")

    def test_require_live_refused(self):
        cmd = [sys.executable, str(ROOT / "reference" / "python" / "xi_pilot_r18.py"), "require-live"]
        job = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(job.returncode, 2)
        self.assertIn("REFUSED", job.stderr)


if __name__ == "__main__":
    unittest.main()
