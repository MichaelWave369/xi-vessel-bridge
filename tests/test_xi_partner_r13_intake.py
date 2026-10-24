"""R13 archive triage. Never runs partner-supplied Python or performs network I/O."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_partner_r10 import validate as validate_r10
from xi_partner_r11 import fixture_bundle, verify as verify_r11
from xi_partner_r12 import make_response_template, make_suite, assess
from xi_partner_r13_intake import (
    ALL_FILES, PIN_FILES, IntakeError, inspect_archive,
)


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def test_files():
    r10, req, attests, pins = fixture_bundle()
    r11 = {
        "request": req, "attestations": attests, "pins": pins,
        "verification": verify_r11(r10, req, attests, pins, now=req["issued_at"] + 1)
    }
    suite = make_suite()
    resp = make_response_template(suite, synthetic_example=True)
    resp["origin"] = "partner_self_report"
    resp["peer_label"] = "xi-fixture"
    docs = {
        "r12_interop/response-template.json": make_response_template(suite),
        "r12_interop/suite.json": suite,
        "r12_interop/synthetic-example-response.json": make_response_template(suite, synthetic_example=True),
        "xi_partner_r10_inspection.json": validate_r10(r10),
        "xi_partner_r10_staging_candidate.json": r10,
        "xi_partner_r11_bundle.json": r11,
        "xi_partner_r12_assessment.json": assess(suite, resp),
        "xi_partner_r12_response.json": resp
    }
    files = {name: encode(obj) for name, obj in docs.items()}
    # A supplied .py member is inert data even if it would fail if executed.
    files["xi_mikey_r10_r11_r12_conformance_runner.py"] = (
        b'raise RuntimeError("NEVER RUN PARTNER CODE")\n'
        b'xi_rev_key = Ed25519PrivateKey.generate()\n'
        b'phi_rev_key = Ed25519PrivateKey.generate()\n'
        b'conn = sqlite3.connect(":memory:")\n'
    )
    pins = {
        "package": "fixture.tar.gz",
        "files": {name: {
            "size_bytes": len(files[name]),
            "sha256": hashlib.sha256(files[name]).hexdigest()
        } for name in sorted(PIN_FILES)}
    }
    files["README_PINS.json"] = encode(pins)
    assert set(files) == ALL_FILES
    return files


def archive(files, *, extra=None, type_override=None):
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as pack:
        for name, data in sorted(files.items()):
            ti = tarfile.TarInfo("./" + name)
            ti.size = len(data)
            pack.addfile(ti, io.BytesIO(data))
        if extra:
            ti = tarfile.TarInfo(extra)
            ti.type = type_override or tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            pack.addfile(ti)
    return blob.getvalue()


class PartnerR13Tests(unittest.TestCase):
    def setUp(self):
        self.files = test_files()
        self.data = archive(self.files)
        self.digest = hashlib.sha256(self.data).hexdigest()

    def test_independent_crypto_and_conformance_reassessment_stays_nonlive(self):
        output = inspect_archive(self.data, self.digest)
        self.assertEqual(output["archive_file_pins_matched"], 9)
        self.assertEqual(output["r12_self_reported_matches"], 8)
        self.assertEqual(output["r12_self_reported_mismatches"], 0)
        self.assertEqual(output["r10_status"], "R10_SYNTHETIC_SHAPE_VERIFIED")
        self.assertEqual(output["r11_status"], "R11_DUAL_REVIEW_SIGNATURES_VERIFIED_NOT_AUTHORIZED")
        self.assertEqual(output["status"], "R13_VERIFIED_BYTES_FIXTURE_ONLY_LIVE_BLOCKED")
        for field in ("archive_source_authenticated", "live_transport_verified",
                      "peer_identity_authenticated", "operator_grant_verified",
                      "safe_to_enable_live_bridge"):
            self.assertIs(output[field], False)
        self.assertIn("R11_SUPPLIED_RUNNER_SELF_GENERATES_BOTH_REVIEW_KEYS",
                      output["blocking_findings"])
        self.assertIn("R12_SUPPLIED_RUNNER_USES_IN_MEMORY_SQLITE_ADAPTER",
                      output["blocking_findings"])

    def test_expected_checksum_is_required_but_not_identity(self):
        with self.assertRaisesRegex(IntakeError, "archive_digest_mismatch"):
            inspect_archive(self.data, "0" * 64)
        with self.assertRaisesRegex(IntakeError, "expected_digest_invalid"):
            inspect_archive(self.data, "trust me")
        self.assertFalse(inspect_archive(self.data, self.digest)["archive_source_authenticated"])

    def test_outer_archive_member_pins_detect_tampering(self):
        files = copy.deepcopy(self.files)
        files["xi_partner_r12_response.json"] += b" "
        raw = archive(files)
        with self.assertRaisesRegex(IntakeError, "pin_size_mismatch"):
            inspect_archive(raw, hashlib.sha256(raw).hexdigest())

    def test_inner_r12_report_mismatch_detected_even_with_updated_pins(self):
        files = copy.deepcopy(self.files)
        report = json.loads(files["xi_partner_r12_assessment.json"])
        report["self_reported_matches"] = 7
        files["xi_partner_r12_assessment.json"] = encode(report)
        pins = json.loads(files["README_PINS.json"])
        name = "xi_partner_r12_assessment.json"
        pins["files"][name] = {
            "size_bytes": len(files[name]), "sha256": hashlib.sha256(files[name]).hexdigest()
        }
        files["README_PINS.json"] = encode(pins)
        raw = archive(files)
        with self.assertRaisesRegex(IntakeError, "r12_report_inconsistent"):
            inspect_archive(raw, hashlib.sha256(raw).hexdigest())

    def test_unknown_or_symlink_members_rejected(self):
        for attack in ("../../etc/passwd", "./r12_interop/unknown.json"):
            raw = archive(self.files, extra=attack)
            with self.subTest(attack=attack), self.assertRaisesRegex(
                IntakeError, "unsafe_or_unknown_archive_member"
            ):
                inspect_archive(raw, hashlib.sha256(raw).hexdigest())

    def test_duplicate_path_and_oversized_members_refused(self):
        blob = io.BytesIO()
        with tarfile.open(fileobj=blob, mode="w:gz") as pack:
            for _ in range(2):
                t = tarfile.TarInfo("./README_PINS.json")
                t.size = len(self.files["README_PINS.json"])
                pack.addfile(t, io.BytesIO(self.files["README_PINS.json"]))
        raw = blob.getvalue()
        with self.assertRaisesRegex(IntakeError, "unsafe_or_unknown_archive_member"):
            inspect_archive(raw, hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(IntakeError, "archive_size_invalid"):
            inspect_archive(b"x" * 65537, hashlib.sha256(b"x" * 65537).hexdigest())

    def test_cli_outputs_unprivileged_report_and_require_live_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            filename = Path(temp) / "received.tar.gz"
            filename.write_bytes(self.data)
            tool = ROOT / "reference" / "python" / "xi_partner_r13_intake.py"
            def call(*extra):
                return subprocess.run(
                    [sys.executable, str(tool), "--archive", str(filename),
                     "--expected-sha256", self.digest, *extra],
                    text=True, capture_output=True, timeout=20
                )
            info = call()
            self.assertEqual(info.returncode, 0, info.stderr[-400:])
            self.assertFalse(json.loads(info.stdout)["safe_to_enable_live_bridge"])
            gate = call("--require-live")
            self.assertEqual(gate.returncode, 2)
            self.assertEqual(json.loads(gate.stdout)["status"],
                             "R13_VERIFIED_BYTES_FIXTURE_ONLY_LIVE_BLOCKED")


if __name__ == "__main__":
    unittest.main()
