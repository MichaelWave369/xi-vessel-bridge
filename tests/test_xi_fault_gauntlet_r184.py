"""R18.4 runs real Ed25519/SQLite local worker pairs for each fault case."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"reference"/"python"))
import xi_fault_gauntlet_r184 as fault

class RealWorkerFaultTests(unittest.TestCase):
    def test_every_real_local_worker_case_matches_expected_and_commit_count(self):
        for name in fault.CASE_IDS:
            with self.subTest(name=name):
                case=fault.case(name)
                self.assertEqual(case["expected"],fault.EXPECTED[name])
                self.assertEqual(case["observed"],fault.EXPECTED[name])
                self.assertIs(case["pass"],True)
                self.assertEqual(case["local_worker_processes"],2)
                self.assertEqual(case["physical_hosts"],1)
                self.assertIs(case["real_ed25519_fixture"],True)
                self.assertIs(case["network_transport"],False)
                self.assertIs(case["live_xi_connected"],False)
                self.assertEqual(case["authority"],"none")
                expected=1 if name in {"baseline","duplicate","restart-replay","receipt-tamper","lost-reply"} else 0
                self.assertEqual(case["receiver_commits"],expected)

    def test_replay_restart_and_receipt_binding(self):
        replay=fault.case("restart-replay")
        self.assertIs(replay["replay_refused_after_restart"],True)
        self.assertEqual(replay["receiver_commits"],1)
        changed=fault.case("receipt-tamper")
        self.assertEqual(changed["observed"],"RESULT_REFUSED")
        self.assertIs(changed["requester_confirmed"],True)  # original, unmodified receipt works

    def test_redacted_report_contains_only_fixed_whitelist_and_zero_external_claims(self):
        summary=fault.report()
        self.assertEqual(summary["status"],"LOCAL_R18_4_GAUNTLET_PASS")
        self.assertEqual(summary["case_count"],14)
        self.assertEqual(summary["passed_count"],14)
        self.assertEqual(tuple(c["scenario_id"] for c in summary["cases"]),fault.CASE_IDS)
        self.assertEqual(summary["independent_xi_receipts"],0)
        self.assertEqual(summary["external_gates_promoted"],0)
        self.assertIs(summary["live_xi_connected"],False)
        self.assertEqual(summary["r18_real_two_host_pilot"],"NOT_RUN")
        self.assertEqual(summary["authority"],"none")
        self.assertEqual(summary["physical_hosts"],1)
        private_fields={"private_key","signature","session_id","peer_pin","payload_b64",
                        "xi_private","token","secret","signed_envelope","request_id",
                        "sender","recipient","public_key","created_at"}
        # A scenario ID can legitimately be named 'signature-tamper'. Inspect
        # actual JSON keys, not substrings in intentionally public scenario names.
        def inspect_keys(node):
            if isinstance(node,dict):
                self.assertTrue(private_fields.isdisjoint(node.keys()))
                for child in node.values(): inspect_keys(child)
            elif isinstance(node,list):
                for child in node: inspect_keys(child)
        inspect_keys(summary)

    def test_case_roster_is_locked_and_require_live_refuses(self):
        with self.assertRaises(RuntimeError):
            fault.case("network-write")
        with self.assertRaises(RuntimeError):
            fault.report(("baseline",))
        p=subprocess.run([sys.executable,str(ROOT/"reference"/"python"/"xi_fault_gauntlet_r184.py"),"require-live"],
                         text=True,capture_output=True,timeout=8)
        self.assertEqual(p.returncode,2)
        self.assertIn("R18_4_REFUSED",p.stderr)

if __name__=="__main__":
    unittest.main()
