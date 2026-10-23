"""R10 candidate partner contract checks (no network, no real secrets)."""
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

from xi_partner_r10 import (
    FORMAT, IntakeError, candidate_template, strict_load,
    synthetic_complete_fixture, validate,
)
SCRIPT = ROOT / "reference" / "python" / "xi_partner_r10.py"


class R10ContractTests(unittest.TestCase):
    def setUp(self):
        self.candidate = candidate_template()
        self.synthetic = synthetic_complete_fixture()

    def expect_invalid(self, changed, error):
        with self.assertRaisesRegex(IntakeError, error):
            validate(changed)

    def test_template_is_actionable_but_not_connected(self):
        report = validate(self.candidate)
        self.assertEqual(report["status"], "R10_INTAKE_INCOMPLETE")
        self.assertIn("missing_or_unverified:transport.event_url", report["missing_requirements"])
        self.assertIn("missing_or_unverified:wire.native_schema_sha256", report["missing_requirements"])
        self.assertFalse(report["live_xi_connected"])
        self.assertFalse(report["transport_invoked"])

    def test_complete_synthetic_contract_is_still_not_live(self):
        report = validate(self.synthetic)
        self.assertEqual(report["status"], "R10_SYNTHETIC_SHAPE_VERIFIED")
        self.assertEqual(report["missing_requirements"], [])
        for key in ("peer_keys_verified", "operator_approval_verified",
                    "supplied_documents_authenticated", "transport_invoked", "live_xi_connected"):
            self.assertFalse(report[key])

    def test_staging_metadata_cannot_self_certify_live_access(self):
        proposal = copy.deepcopy(self.synthetic)
        proposal["classification"] = "staging_candidate"
        proposal["transport"]["event_url"] = "https://xi-staging.peer-domain.tld/v1/events"
        # Name and domain are fabricated metadata for TEST ONLY; no request made.
        report = validate(proposal)
        self.assertEqual(report["status"], "R10_STAGING_CANDIDATE_REQUIRES_JOINT_REVIEW")
        self.assertFalse(report["operator_approval_verified"])
        self.assertFalse(report["live_xi_connected"])

    def test_admin_shell_and_other_unapproved_scopes_refused(self):
        for scopes in (["admin"], ["shell.exec"], ["filesystem.write"],
                       ["capsule.read", "capsule.read"], [], ["capsule.read", "admin"]):
            proposal = copy.deepcopy(self.synthetic)
            proposal["authorization"]["scopes"] = scopes
            with self.subTest(scopes=scopes):
                self.expect_invalid(proposal, "unapproved_or_duplicate_scope")

    def test_table_reply_needs_scope_endpoint_and_human_evidence(self):
        proposal = copy.deepcopy(self.synthetic)
        proposal["authorization"]["scopes"].append("table.reply")
        report = validate(proposal)
        self.assertIn("missing_or_unverified:table.reply_endpoint", report["missing_requirements"])
        proposal["transport"]["reply_url"] = "https://xi-fixture.example.invalid/v1/fixture/reply"
        report = validate(proposal)
        self.assertEqual(report["status"], "R10_SYNTHETIC_SHAPE_VERIFIED")
        self.assertFalse(report["operator_approval_verified"])
        proposal["room"]["human_approval_record_sha256"] = None
        report = validate(proposal)
        self.assertIn("missing_or_unverified:table.reply_explicit_human_approval",
                      report["missing_requirements"])

    def test_reply_url_without_reply_scope_refused(self):
        proposal = copy.deepcopy(self.synthetic)
        proposal["transport"]["reply_url"] = "https://xi-fixture.example.invalid/replies"
        self.expect_invalid(proposal, "reply_url_without_reply_scope")

    def test_no_public_webhook_or_redirects_from_candidate(self):
        for mode in ("inbound_webhook", "any", "auto_admin", None):
            proposal = copy.deepcopy(self.synthetic)
            proposal["transport"]["mode"] = mode
            with self.subTest(mode=mode):
                self.expect_invalid(proposal, "unsolicited_inbound_transport_denied")
        proposal = copy.deepcopy(self.synthetic)
        proposal["transport"]["follows_redirects"] = True
        self.expect_invalid(proposal, "redirect_following_denied")

    def test_reject_private_urls_tokens_in_query_and_wrong_schemes(self):
        bad_urls = [
            "http://xi-staging.peer-domain.tld/v1/events",
            "https://127.0.0.1/v1/events",
            "https://localhost/v1/events",
            "https://myhost.local/v1/events",
            "https://service.internal/v1/events",
            "https://u:p@xi-staging.peer-domain.tld/v1/events",
            "https://xi-staging.peer-domain.tld/v1/events?key=secret",
            "file:///home/mikey/secret",
            "https://[::1]/v1/events",
            "https://169.254.169.254/v1/events",
        ]
        for url in bad_urls:
            proposal = copy.deepcopy(self.synthetic)
            proposal["transport"]["event_url"] = url
            with self.subTest(url=url):
                self.assertIn("missing_or_unverified:transport.event_url",
                              validate(proposal)["missing_requirements"])
        proposal = copy.deepcopy(self.synthetic)
        proposal["classification"] = "staging_candidate"
        self.assertIn("missing_or_unverified:transport.event_url",
                      validate(proposal)["missing_requirements"])

    def test_secret_values_and_fields_refused_even_in_synthetic(self):
        for value in ("Bearer fakefakefake", "-----BEGIN PRIVATE KEY-----\nfake",
                      "sk-1234567890000000", "uploads/mikey-tessera-25661.key"):
            p = copy.deepcopy(self.synthetic)
            p["wire"]["native_tessera_version"] = value
            with self.subTest(value=value):
                self.expect_invalid(p, "secret_like_value_prohibited")
        p = copy.deepcopy(self.synthetic)
        p["transport"]["api_key"] = "x"
        self.expect_invalid(p, "secret_field_prohibited")

    def test_extra_fields_unknown_versions_and_privilege_mode_denied(self):
        p = copy.deepcopy(self.synthetic)
        p["format"] = "xi.real.unverified"
        self.expect_invalid(p, "unknown_contract_version")
        p = copy.deepcopy(self.synthetic)
        p["classification"] = "production"
        self.expect_invalid(p, "classification_forbidden")
        p = copy.deepcopy(self.synthetic)
        p["peer"]["admin"] = True
        self.expect_invalid(p, "contract_section_invalid_peer")
        p = copy.deepcopy(self.synthetic)
        p["peer"]["recipient"] = p["peer"]["sender"]
        self.expect_invalid(p, "same_peer_denied")

    def test_missing_and_invalid_document_digests_do_not_pass(self):
        for value in (None, "0" * 64, "a" * 63, "not-a-digest"):
            p = copy.deepcopy(self.synthetic)
            p["evidence"]["official_transport_doc_sha256"] = value
            with self.subTest(value=value):
                report = validate(p)
                self.assertIn("missing_or_unverified:evidence.official_transport_doc_sha256",
                              report["missing_requirements"])

    def test_candidate_digest_stable_across_key_order_and_sensitive_values_not_echoed(self):
        one = validate(self.synthetic)
        rearranged = dict(reversed(list(self.synthetic.items())))
        self.assertEqual(one["contract_sha256"], validate(rearranged)["contract_sha256"])
        self.assertNotIn("xi-fixture.example.invalid", json.dumps(one))

    def test_strict_file_loader_rejects_duplicate_keys_and_oversize(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "candidate.json"
            path.write_text('{"format":"a","format":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(IntakeError, "duplicate_json_key"):
                strict_load(str(path))
            path.write_bytes(b"x" * 32769)
            with self.assertRaisesRegex(IntakeError, "input_file_size_invalid"):
                strict_load(str(path))

    def test_three_step_cli_never_calls_live_network(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            draft, fixture = root / "draft.json", root / "synthetic.json"
            def run(*args):
                return subprocess.run([sys.executable, str(SCRIPT), *args],
                                      capture_output=True, text=True, timeout=20)
            first = run("template", "--out", str(draft))
            self.assertEqual(first.returncode, 0, first.stderr[-400:])
            self.assertEqual(json.loads(first.stdout)["status"], "R10_INTAKE_INCOMPLETE")
            strict = run("inspect", "--file", str(draft), "--require-complete")
            self.assertEqual(strict.returncode, 2)
            created = run("synthetic", "--out", str(fixture))
            self.assertEqual(created.returncode, 0, created.stderr[-400:])
            checked = run("inspect", "--file", str(fixture), "--require-complete")
            self.assertEqual(checked.returncode, 0, checked.stderr[-400:])
            self.assertEqual(json.loads(checked.stdout)["status"], "R10_SYNTHETIC_SHAPE_VERIFIED")
            again = run("synthetic", "--out", str(fixture))
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(strict_load(str(fixture))["format"], FORMAT)


if __name__ == "__main__":
    unittest.main()
