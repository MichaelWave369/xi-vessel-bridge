"""R17 roadmap claim-boundary and readiness negative controls."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
import xi_shared_roadmap_r17 as roadmap


class RoadmapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = ROOT / "roadmap" / "bridge-roadmap.json"
        cls.seed = json.loads(cls.source.read_text(encoding="utf-8"))

    def modified(self):
        return copy.deepcopy(self.seed)

    def refuses(self, doc):
        with self.assertRaises(roadmap.RoadmapRefused):
            roadmap.report(doc)

    def test_baseline_inspection(self):
        result = roadmap.report(self.modified())
        self.assertEqual(result["external_pilot_status"], "BLOCKED")
        self.assertEqual(result["local_fixture_milestones"], ["R15", "R16"])
        self.assertEqual(len(result["r17_missing_gates"]), 16)
        self.assertFalse(result["live_xi_connected"])
        self.assertEqual(result["trusted_remote_capability_count"], 0)

    def test_public_13_capabilities_not_pretended_confirmed(self):
        result = roadmap.report(self.modified())
        self.assertEqual(result["advertised_preview_counts"], {"capabilities": 13, "doors": 12})
        self.assertEqual(result["trusted_remote_capability_count"], 0)

    def test_live_flag_is_refused(self):
        doc = self.modified()
        doc["live_xi_connected"] = True
        self.refuses(doc)

    def test_authority_claim_is_refused(self):
        doc = self.modified()
        doc["authority"] = "remote-admin"
        self.refuses(doc)

    def test_extra_grant_is_refused(self):
        doc = self.modified()
        doc["access_token"] = "some-value"
        self.refuses(doc)

    def test_unverified_public_capabilities_cannot_be_verified_in_place(self):
        doc = self.modified()
        doc["xi_public_preview"]["verified_capability_ids"] = ["arbitrary-model.invoke"]
        self.refuses(doc)

    def test_unverified_doors_cannot_be_confirmed_in_place(self):
        doc = self.modified()
        doc["xi_public_preview"]["verified_door_ids"] = ["door-one"]
        self.refuses(doc)

    def test_unknown_or_duplicate_gate_is_rejected(self):
        doc = self.modified()
        doc["gates"][0]["id"] = "shell"
        self.refuses(doc)
        doc = self.modified()
        doc["gates"][0]["id"] = doc["gates"][1]["id"]
        self.refuses(doc)

    def test_approval_claim_without_independent_evidence_is_refused(self):
        doc = self.modified()
        doc["gates"][0]["state"] = "externally_verified"
        self.refuses(doc)

    def test_candidates_remain_unverified_even_if_all_marked_candidate(self):
        doc = self.modified()
        for gate in doc["gates"]:
            gate["state"] = "candidate_unverified"
        output = roadmap.report(doc)
        self.assertEqual(output["r17_missing_gates"], [])
        self.assertEqual(len(output["r17_unverified_candidate_gates"]), 16)
        self.assertEqual(output["external_pilot_status"], "BLOCKED")

    def test_false_r17_promotion_refused(self):
        doc = self.modified()
        doc["milestones"][2]["state"] = "passed"
        self.refuses(doc)

    def test_dependency_bypass_refused(self):
        doc = self.modified()
        doc["milestones"][3]["depends_on"] = ["R15"]
        self.refuses(doc)

    def test_r17_cannot_drop_identity_gate(self):
        doc = self.modified()
        doc["milestones"][2]["gate_ids"].remove("identity")
        self.refuses(doc)

    def test_rejects_external_endpoint_or_scheme(self):
        doc = self.modified()
        doc["xi_public_preview"]["source"] = "http://example.org/live"
        self.refuses(doc)

    def test_future_placeholder_cannot_claim_verified_capability(self):
        doc = self.modified()
        doc["capability_candidates"][1]["state"] = "authorized"
        self.refuses(doc)

    def test_refuse_changed_count_without_source_review(self):
        doc = self.modified()
        doc["xi_public_preview"]["capabilities_count"] = 14
        self.refuses(doc)

    def test_require_live_always_fails(self):
        completed = subprocess.run([
            sys.executable, str(ROOT / "reference" / "python" / "xi_shared_roadmap_r17.py"),
            "--file", str(self.source), "--require-live"
        ], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("BLOCKED", completed.stdout)
        self.assertIn("R17_REFUSED", completed.stderr)

    def test_default_cli_inspection_passes(self):
        completed = subprocess.run([
            sys.executable, str(ROOT / "reference" / "python" / "xi_shared_roadmap_r17.py")
        ], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0)
        result = json.loads(completed.stdout)
        self.assertEqual(result["external_pilot_status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
