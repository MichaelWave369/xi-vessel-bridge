"""R11 reviewer signature fixtures: challenge contract tampering, forgery, replay."""
from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
from xi_partner_r10 import synthetic_complete_fixture
from xi_partner_r11 import (
    ReviewError, ReviewReplayLedger, check_request, fixture_bundle, make_attestation,
    make_request, read_private_signer, sha256, verify,
)

CLI = ROOT / "reference" / "python" / "xi_partner_r11.py"
NOW = int(time.time())


class R11ReviewTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.request, self.attest, self.pins = fixture_bundle()

    def rejected(self, pattern, *, contract=None, request=None, attest=None, pins=None, now=None):
        with self.assertRaisesRegex(ReviewError, pattern):
            verify(self.contract if contract is None else contract,
                   self.request if request is None else request,
                   self.attest if attest is None else attest,
                   self.pins if pins is None else pins,
                   now=now)

    def test_two_signatures_prove_review_key_control_not_authority(self):
        output = verify(self.contract, self.request, self.attest, self.pins)
        self.assertEqual(output["status"], "R11_DUAL_REVIEW_SIGNATURES_VERIFIED_NOT_AUTHORIZED")
        self.assertEqual(output["review_signatures_verified"], 2)
        for name in ("human_approval_verified", "keys_independently_authenticated",
                     "grant_issued", "transport_invoked", "live_xi_connected"):
            self.assertIs(output[name], False)

    def test_changing_contract_after_review_fails(self):
        changed = copy.deepcopy(self.contract)
        changed["room"]["room_id"] = "another-fixture-room"
        self.rejected("review_contract_binding_mismatch", contract=changed)
        changed = copy.deepcopy(self.contract)
        changed["limits"]["timeout_seconds"] += 1
        self.rejected("review_contract_binding_mismatch", contract=changed)

    def test_scope_escalation_cannot_reuse_review(self):
        changed = copy.deepcopy(self.contract)
        changed["authorization"]["scopes"].append("table.reply")
        changed["transport"]["reply_url"] = "https://xi-fixture.example.invalid/v1/reply"
        self.rejected("review_contract_binding_mismatch", contract=changed)
        changed["authorization"]["scopes"].append("admin")
        with self.assertRaises(ValueError):
            verify(changed, self.request, self.attest, self.pins)

    def test_requires_both_roles_no_single_party_shortcut(self):
        partial = copy.deepcopy(self.attest)
        del partial["phi_reviewer"]
        self.rejected("both_reviewers_required", attest=partial)
        partial = copy.deepcopy(self.attest)
        partial["phi_reviewer"] = partial["xi_reviewer"]
        self.rejected("attestation_unbound", attest=partial)

    def test_swapped_or_unknown_pins_fail(self):
        changed = copy.deepcopy(self.pins)
        keys = changed["reviewer_signing_public_keys"]
        keys["xi_reviewer"], keys["phi_reviewer"] = keys["phi_reviewer"], keys["xi_reviewer"]
        self.rejected("review_signature_invalid", pins=changed)
        changed = copy.deepcopy(self.pins)
        changed["reviewer_signing_public_keys"]["xi_reviewer"] = (
            changed["reviewer_signing_public_keys"]["phi_reviewer"])
        self.rejected("reviewers_must_use_distinct_keys", pins=changed)
        changed = copy.deepcopy(self.pins)
        changed["role"] = "admin"
        self.rejected("review_pins_invalid", pins=changed)

    def test_self_asserted_approval_flags_forbidden(self):
        changed = copy.deepcopy(self.attest)
        changed["xi_reviewer"]["statement"]["decision"] = "authorize_prod_model_execution"
        self.rejected("attestation_unbound", attest=changed)
        changed = copy.deepcopy(self.request)
        changed["intent"] = "enable_admin"
        self.rejected("review_contract_binding_mismatch", request=changed)
        changed = copy.deepcopy(self.pins)
        changed["origin"] = "hunter_verified_live"
        self.rejected("review_pins_invalid", pins=changed)

    def test_substitute_unpinned_key_denied(self):
        signing = Ed25519PrivateKey.generate()
        changed = copy.deepcopy(self.attest)
        changed["xi_reviewer"] = make_attestation(
            self.request, self.contract, "xi_reviewer", signing)
        self.rejected("review_signature_invalid", attest=changed)

    def test_forged_signed_at_and_signature_denied(self):
        changed = copy.deepcopy(self.attest)
        changed["phi_reviewer"]["statement"]["signed_at"] += 1
        self.rejected("review_signature_invalid", attest=changed)
        changed = copy.deepcopy(self.attest)
        changed["phi_reviewer"]["signature_b64"] = base64.b64encode(b"\0"*64).decode()
        self.rejected("review_signature_invalid", attest=changed)

    def test_expired_future_and_incomplete_contract_denied(self):
        self.rejected("review_request_expired_or_future", now=self.request["expires_at"])
        self.rejected("review_request_expired_or_future", now=self.request["issued_at"]-31)
        incomplete = synthetic_complete_fixture()
        incomplete["evidence"]["official_transport_doc_sha256"] = None
        with self.assertRaisesRegex(ReviewError, "contract_incomplete"):
            make_request(incomplete)

    def test_distinct_request_id_cannot_reuse_attestations(self):
        fresh = make_request(self.contract)
        self.rejected("attestation_unbound", request=fresh)

    def test_replay_rejected_after_database_restart(self):
        with tempfile.TemporaryDirectory() as root:
            db = str(Path(root) / "review-ledger.sqlite")
            ledger = ReviewReplayLedger(db)
            ledger.reserve(self.request)
            with self.assertRaisesRegex(ReviewError, "review_replayed"):
                ledger.reserve(self.request)
            ledger.close()
            again = ReviewReplayLedger(db)
            try:
                with self.assertRaisesRegex(ReviewError, "review_replayed"):
                    again.reserve(self.request)
                conflicting = copy.deepcopy(self.request)
                conflicting["contract_sha256"] = "0" * 64
                with self.assertRaisesRegex(ReviewError, "review_id_conflict"):
                    again.reserve(conflicting)
            finally:
                again.close()

    def test_private_signer_file_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            keyfile = Path(root) / "reviewer.raw"
            signer = Ed25519PrivateKey.generate()
            from cryptography.hazmat.primitives import serialization
            private = signer.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption())
            fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as target:
                target.write(private)
            read = read_private_signer(str(keyfile))
            self.assertEqual(
                read.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw),
                signer.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw))
            if os.name == "posix":
                keyfile.chmod(0o644)
                with self.assertRaisesRegex(ReviewError, "insecure_signing_key_permissions"):
                    read_private_signer(str(keyfile))
            link = Path(root) / "symlink.raw"
            try:
                link.symlink_to(keyfile)
            except (OSError, NotImplementedError):
                return
            with self.assertRaisesRegex(ReviewError, "signing_key_unavailable"):
                read_private_signer(str(link))

    def test_public_demo_bundle_contains_no_identity_secrets(self):
        raw = json.dumps({"contract":self.contract,"request":self.request,
                          "attestation":self.attest,"pins":self.pins})
        for value in ("private_key", "Bearer ", "mikey-tessera-25661.key", "XI_TABLE_WEBHOOK_SECRET"):
            self.assertNotIn(value, raw)
        self.assertEqual(self.pins["origin"], "synthetic_self_issued")

    def test_fixture_cli_two_process_verification_then_replay_denial(self):
        with tempfile.TemporaryDirectory(prefix="r11-check-") as root:
            directory = Path(root)
            fixture_dir = directory / "bundle"
            def run(*args):
                return subprocess.run([sys.executable, str(CLI), *args],
                                      capture_output=True, text=True, timeout=20)
            issued = run("fixture", "--dir", str(fixture_dir))
            self.assertEqual(issued.returncode, 0, issued.stderr[-600:])
            args = ["verify", "--contract", str(fixture_dir / "contract.json"),
                    "--request", str(fixture_dir / "request.json"),
                    "--xi-attestation", str(fixture_dir / "xi-attestation.json"),
                    "--phi-attestation", str(fixture_dir / "phi-attestation.json"),
                    "--pins", str(fixture_dir / "self-issued-demo-pins.json"),
                    "--ledger", str(directory / "verified.sqlite3")]
            checked = run(*args)
            self.assertEqual(checked.returncode, 0, checked.stderr[-600:])
            result = json.loads(checked.stdout)
            self.assertEqual(result["status"], "R11_DUAL_REVIEW_SIGNATURES_VERIFIED_NOT_AUTHORIZED")
            self.assertIs(result["grant_issued"], False)
            replay = run(*args)
            self.assertNotEqual(replay.returncode, 0)
            self.assertIn("review_replayed", replay.stderr)
            self.assertEqual(set(p.name for p in fixture_dir.iterdir()),
                             {"contract.json", "request.json", "xi-attestation.json",
                              "phi-attestation.json", "self-issued-demo-pins.json"})


if __name__ == "__main__":
    unittest.main()
