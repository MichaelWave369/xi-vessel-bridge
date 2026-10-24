"""R12 portable conformance claims: exact-byte positive and deny-by-default negatives.

All examples are synthetic and the "pass" example is intentionally fabricated.
The assessor NEVER authenticates a partner, executes input, or contacts Xi.
"""
from __future__ import annotations

import base64
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

from xi_partner_r12 import (
    ExerciseError, assess, canonical, digest, make_response_template,
    make_suite, read_json,
)

CLI = ROOT / "reference" / "python" / "xi_partner_r12.py"


class R12PortableConformanceTests(unittest.TestCase):
    def setUp(self):
        self.suite = make_suite()
        self.template = make_response_template(self.suite)
        self.example = make_response_template(self.suite, synthetic_example=True)

    def example_obs(self, name):
        return next(x for x in self.example["observations"] if x["case_id"] == name)

    def test_suite_reproducible_and_exact_but_not_real_xi_protocol(self):
        self.assertEqual(canonical(make_suite()), canonical(self.suite))
        self.assertEqual(len(self.suite["cases"]), 8)
        self.assertEqual(len({x["request_id"] for x in self.suite["cases"]}), 8)
        self.assertIn("Not Xi/TESSERA-native", self.suite["notice"])
        self.assertEqual(self.suite["classification"], "offline_synthetic_exercises_only")

    def test_exact_four_names_and_unicode_byte_hashes(self):
        cases = {x["case_id"]: x for x in self.suite["cases"]}
        four = cases["four_name_opaque_bytes"]
        original = base64.b64decode(four["payload_b64"], validate=True)
        self.assertEqual(original, b"xi-vessel-bridge\nCommonline\nFieldAccord\nthink-tank")
        self.assertEqual(hashlib.sha256(original).hexdigest(), four["payload_sha256"])
        uni = cases["unicode_exact_bytes"]
        raw = base64.b64decode(uni["payload_b64"], validate=True)
        self.assertIn("Ξ ⋈ Φ", raw.decode())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), uni["payload_sha256"])

    def test_incomplete_partner_template_remains_unverified(self):
        result = assess(self.suite, self.template)
        self.assertEqual(result["status"], "R12_PARTNER_EVIDENCE_PENDING")
        self.assertEqual(result["unresolved"], 8)
        self.assertEqual(result["self_reported_matches"], 0)
        self.assertFalse(result["actual_xi_runtime_observed"])
        self.assertFalse(result["live_xi_connected"])

    def test_self_reported_synthetic_example_matches_without_proving_identity(self):
        result = assess(self.suite, self.example)
        self.assertEqual(result["status"], "R12_SELF_REPORTED_MATCHES_NOT_AUTHENTICATED")
        self.assertEqual(result["self_reported_matches"], 8)
        self.assertEqual(result["unresolved"], 0)
        self.assertEqual(result["response_origin"], "synthetic_local_example")
        for key in ("partner_identity_authenticated", "actual_xi_runtime_observed",
                    "native_xi_tessera_verified", "grant_or_permission_verified",
                    "tool_or_model_executed", "live_xi_connected"):
            self.assertIs(result[key], False)

    def test_synthetic_success_cannot_become_authenticated_just_by_claiming_it(self):
        fake = copy.deepcopy(self.example)
        fake["origin"] = "partner_self_report"
        fake["peer_label"] = "xi-simulated"
        result = assess(self.suite, fake)
        self.assertEqual(result["status"], "R12_SELF_REPORTED_MATCHES_NOT_AUTHENTICATED")
        self.assertFalse(result["partner_identity_authenticated"])
        self.assertFalse(result["actual_xi_runtime_observed"])

    def test_payload_bytes_or_expected_results_cannot_be_edited_in_suite(self):
        edited = copy.deepcopy(self.suite)
        edited["cases"][0]["expected_decision"] = "denied"
        with self.assertRaisesRegex(ExerciseError, "suite_fixture_mismatch"):
            assess(edited, self.template)
        edited = copy.deepcopy(self.suite)
        edited["cases"][1]["payload_b64"] = "YQ=="
        with self.assertRaisesRegex(ExerciseError, "suite_fixture_mismatch"):
            assess(edited, self.template)

    def test_wrong_manifest_digest_denied(self):
        response = copy.deepcopy(self.example)
        response["suite_sha256"] = "0" * 64
        with self.assertRaisesRegex(ExerciseError, "wrong_suite_digest"):
            assess(self.suite, response)

    def test_exact_byte_mismatch_reported_not_silently_passed(self):
        observed = self.example_obs("unicode_exact_bytes")
        observed["observed_payload_sha256"] = "0" * 64
        result = assess(self.suite, self.example)
        self.assertEqual(result["status"], "R12_SELF_REPORTED_MISMATCHES")
        self.assertEqual(result["self_reported_mismatches"], 1)

    def test_provenance_loss_is_mismatch(self):
        observed = self.example_obs("provenance_preserved")
        observed["observed_provenance_sha256"] = "f" * 64
        report = assess(self.suite, self.example)
        self.assertEqual(report["status"], "R12_SELF_REPORTED_MISMATCHES")

    def test_tamper_refusal_requires_zero_processing(self):
        observed = self.example_obs("declared_digest_tampered")
        self.assertEqual(observed["decision"], "denied")
        self.assertEqual(observed["processing_count"], 0)
        observed["processing_count"] = 1
        report = assess(self.suite, self.example)
        self.assertEqual(report["self_reported_mismatches"], 1)

    def test_scope_revocation_unknown_tool_never_processed(self):
        for name in ("wrong_room_denied", "revoked_grant_denied",
                     "unknown_tool_never_executed"):
            observed = self.example_obs(name)
            self.assertEqual(observed["processing_count"], 0)
            self.assertEqual(observed["decision"], "denied")
            observed["decision"] = "accepted"
            with self.subTest(case=name):
                self.assertEqual(assess(self.suite, self.example)["status"],
                                 "R12_SELF_REPORTED_MISMATCHES")
            observed["decision"] = "denied"

    def test_duplicate_delivery_requires_single_operation(self):
        observed = self.example_obs("duplicate_delivery_idempotent")
        observed["processing_count"] = 2
        report = assess(self.suite, self.example)
        self.assertEqual(report["self_reported_mismatches"], 1)

    def test_partial_unsupported_is_honestly_unresolved(self):
        observation = self.example_obs("provenance_preserved")
        observation.update(status="unsupported", decision=None,
                           processing_count=None, denial_code=None,
                           observed_payload_sha256=None,
                           observed_provenance_sha256=None)
        report = assess(self.suite, self.example)
        self.assertEqual(report["unresolved"], 1)
        self.assertEqual(report["status"], "R12_PARTNER_EVIDENCE_PENDING")

    def test_unmeasured_status_must_not_claim_counts_or_acceptance(self):
        observation = self.template["observations"][0]
        observation["decision"] = "accepted"
        with self.assertRaisesRegex(ExerciseError, "unmeasured_case_has_claims"):
            assess(self.suite, self.template)

    def test_unknown_missing_or_duplicate_case_refused(self):
        dup = copy.deepcopy(self.example)
        dup["observations"][1]["case_id"] = dup["observations"][0]["case_id"]
        with self.assertRaisesRegex(ExerciseError, "duplicate_or_unknown_case"):
            assess(self.suite, dup)
        bad = copy.deepcopy(self.example)
        bad["observations"][0]["case_id"] = "pretend-live-xi"
        with self.assertRaisesRegex(ExerciseError, "duplicate_or_unknown_case"):
            assess(self.suite, bad)
        missing = copy.deepcopy(self.example)
        missing["observations"].pop()
        with self.assertRaisesRegex(ExerciseError, "observation_count_invalid"):
            assess(self.suite, missing)

    def test_unknown_fields_and_invalid_claims_refused(self):
        bad = copy.deepcopy(self.example)
        bad["credentials"] = "do-not-send"
        with self.assertRaisesRegex(ExerciseError, "response_shape_invalid"):
            assess(self.suite, bad)
        bad = copy.deepcopy(self.example)
        bad["observations"][0]["real_xi_confirmed"] = True
        with self.assertRaisesRegex(ExerciseError, "observation_shape_invalid"):
            assess(self.suite, bad)
        bad = copy.deepcopy(self.example)
        bad["peer_label"] = "https://server/private"
        with self.assertRaisesRegex(ExerciseError, "peer_label_invalid"):
            assess(self.suite, bad)
        bad = copy.deepcopy(self.example)
        bad["origin"] = "verified-real-xi"
        with self.assertRaisesRegex(ExerciseError, "response_origin_invalid"):
            assess(self.suite, bad)

    def test_invalid_processing_count_refused(self):
        for value in (True, -1, "0", 3, 1.0):
            bad = copy.deepcopy(self.example)
            bad["observations"][0]["processing_count"] = value
            with self.subTest(value=value), self.assertRaisesRegex(
                    ExerciseError, "invalid_measured_outcome"):
                assess(self.suite, bad)

    def test_cli_generate_assess_failclosed_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="xi-r12-") as tmp:
            output = Path(tmp) / "interop"
            def run(*args):
                return subprocess.run([sys.executable, str(CLI), *args],
                                      text=True, capture_output=True, timeout=20)
            generated = run("generate", "--dir", str(output))
            self.assertEqual(generated.returncode, 0, generated.stderr[-600:])
            self.assertEqual(json.loads(generated.stdout)["status"],
                             "R12_PARTNER_EVIDENCE_PENDING")
            suite, draft, fake = [
                output / name for name in (
                    "suite.json", "response-template.json",
                    "synthetic-example-response.json")]
            pending = run("assess", "--suite", str(suite), "--response", str(draft),
                          "--require-all-matches")
            self.assertEqual(pending.returncode, 2)
            good = run("assess", "--suite", str(suite), "--response", str(fake),
                       "--require-all-matches")
            self.assertEqual(good.returncode, 0, good.stderr[-600:])
            self.assertEqual(json.loads(good.stdout)["status"],
                             "R12_SELF_REPORTED_MATCHES_NOT_AUTHENTICATED")
            overwrite = run("generate", "--dir", str(output))
            self.assertNotEqual(overwrite.returncode, 0)
            self.assertEqual(read_json(str(suite)), make_suite())

    def test_strict_json_and_size_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bad.json"
            target.write_text('{"format":"a","format":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ExerciseError, "duplicate_json_key"):
                read_json(str(target))
            target.write_bytes(b"a" * 80001)
            with self.assertRaisesRegex(ExerciseError, "input_size_invalid"):
                read_json(str(target))


if __name__ == "__main__":
    unittest.main()
