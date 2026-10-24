"""R14: prove bytes before claiming authority, and retain the live deny-by-default gate."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_partner_r10 import validate as validate_r10
from xi_partner_r11 import make_request, make_attestation, verify as verify_r11
from xi_partner_r14_evidence import (
    IntakeError, decode_public_key_base64, review_public_evidence
)
from test_xi_partner_r13_intake import archive, test_files


def enc(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def signed_public_bytes_fixture():
    """All signers below are independent *synthetic test variables* only."""
    public = b"p" * 32
    transport = b"Xi operator test fixture only; not a published real specification\n"
    schema = b'{"not":"real native Xi"}'
    files = test_files()
    contract = json.loads(files["xi_partner_r10_staging_candidate.json"])
    contract["evidence"]["out_of_band_peer_signing_key_sha256"] = digest(public)
    contract["evidence"]["official_transport_doc_sha256"] = digest(transport)
    contract["wire"]["native_schema_sha256"] = digest(schema)
    req = make_request(contract)
    keys = {role: Ed25519PrivateKey.generate()
            for role in ("xi_reviewer", "phi_reviewer")}
    attestations = {role: make_attestation(req, contract, role, key, now=req["issued_at"])
                    for role, key in keys.items()}
    pins = {
        "format": "xi.phi.dual-review.pins.r11",
        "origin": "synthetic_self_issued",
        "reviewer_signing_public_keys": {
            role: base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )).decode() for role, key in keys.items()
        }
    }
    bundle = {
        "request": req, "attestations": attestations, "pins": pins,
        "verification": verify_r11(contract, req, attestations, pins, now=req["issued_at"])
    }
    files["xi_partner_r10_staging_candidate.json"] = enc(contract)
    files["xi_partner_r10_inspection.json"] = enc(validate_r10(contract))
    files["xi_partner_r11_bundle.json"] = enc(bundle)
    pins_doc = json.loads(files["README_PINS.json"])
    for name in ("xi_partner_r10_staging_candidate.json",
                 "xi_partner_r10_inspection.json", "xi_partner_r11_bundle.json"):
        pins_doc["files"][name] = {
            "size_bytes": len(files[name]), "sha256": digest(files[name])
        }
    files["README_PINS.json"] = enc(pins_doc)
    raw = archive(files)
    return raw, public, transport, schema


class R14PublicEvidenceGateTests(unittest.TestCase):
    def test_baseline_missing_public_artifacts_and_presigned_phi_never_connect(self):
        raw = archive(test_files())
        result = review_public_evidence(raw, digest(raw))
        self.assertEqual(result["status"],
                         "R14_FIXTURE_INTEGRITY_VERIFIED_INDEPENDENT_EVIDENCE_HOLD")
        self.assertEqual(result["archive_file_pins_matched"], 9)
        self.assertEqual(result["r12_self_reported_matches"], 8)
        self.assertEqual(result["public_artifact_checks"]["peer_public_key"]["status"],
                         "MISSING_BYTES")
        self.assertIn("PARTNER_ARCHIVE_CONTAINS_PRE_SIGNED_PHI_REVIEWER_SLOT",
                      result["blocking_findings"])
        self.assertIn("LIVE_XI_TRANSPORT_NOT_WITNESSED", result["blocking_findings"])
        self.assertFalse(result["independent_phi_review_verified"])
        self.assertFalse(result["safe_to_enable_live_bridge"])

    def test_all_public_bytes_match_digests_still_not_authentication(self):
        raw, public, transport, schema = signed_public_bytes_fixture()
        result = review_public_evidence(raw, digest(raw),
                                        public_key=public, transport_spec=transport,
                                        native_schema=schema)
        for label in ("peer_public_key", "xi_transport_spec", "xi_native_schema"):
            self.assertEqual(result["public_artifact_checks"][label]["status"],
                             "HASH_MATCH_UNAUTHENTICATED")
        self.assertFalse(result["public_bytes_hashes_prove_identity"])
        self.assertFalse(result["durable_runtime_verified"])
        self.assertFalse(result["safe_to_enable_live_bridge"])

    def test_exact_public_key_mismatch_must_be_observable(self):
        raw, public, transport, schema = signed_public_bytes_fixture()
        output = review_public_evidence(
            raw, digest(raw), public_key=b"x" * 32,
            transport_spec=transport, native_schema=schema)
        self.assertEqual(output["public_artifact_checks"]["peer_public_key"]["status"],
                         "HASH_MISMATCH")
        self.assertIn("PEER_PUBLIC_KEY_HASH_MISMATCH", output["blocking_findings"])
        self.assertEqual(output["public_artifact_checks"]["peer_public_key"]["measured_sha256"],
                         digest(b"x" * 32))

    def test_transport_schema_bytes_are_compared_independently(self):
        raw, public, transport, schema = signed_public_bytes_fixture()
        output = review_public_evidence(
            raw, digest(raw), public_key=public,
            transport_spec=transport + b"tamper", native_schema=b"{}")
        self.assertEqual(output["public_artifact_checks"]["xi_transport_spec"]["status"],
                         "HASH_MISMATCH")
        self.assertEqual(output["public_artifact_checks"]["xi_native_schema"]["status"],
                         "HASH_MISMATCH")

    def test_public_32byte_key_from_partner_message_does_not_match_claimed_pin(self):
        # A public key string printed in the v2 room announcement; not a secret,
        # not authenticated, and deliberately NEVER a trusted identity fixture.
        advertised = "eibfeafwQ0b2R62pV88k31D0hWbaN5VdeD7naxdBjn4="
        raw = decode_public_key_base64(advertised)
        self.assertEqual(len(raw), 32)
        self.assertEqual(digest(raw),
                         "9ff709023bafa53666a5e6ed85d770eeaf2371a71187749f6d831ea147b13d2d")
        self.assertNotEqual(digest(raw),
                            "faefc83d7756724aadc078fe122e5d98d230bebf3ad77e576f9918da67fc31dc")

    def test_untrusted_bytes_and_key_sizes_are_rejected(self):
        raw = archive(test_files())
        with self.assertRaisesRegex(IntakeError, "archive_digest_mismatch"):
            review_public_evidence(raw, "0" * 64)
        with self.assertRaisesRegex(IntakeError, "public_key_raw_ed25519_required"):
            review_public_evidence(raw, digest(raw), public_key=b"short")
        with self.assertRaisesRegex(IntakeError, "public_key"):
            decode_public_key_base64("a" * 44)
        with self.assertRaisesRegex(IntakeError, "xi_native_schema_size_invalid"):
            review_public_evidence(raw, digest(raw), native_schema=b"")

    def test_cli_blocks_live_even_when_all_synthetic_byte_hashes_match(self):
        raw, public, transport, schema = signed_public_bytes_fixture()
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp)
            archive_path = d / "partner.tar.gz"
            transport_path, schema_path = d / "transport.md", d / "schema.json"
            archive_path.write_bytes(raw)
            transport_path.write_bytes(transport)
            schema_path.write_bytes(schema)
            args = [
                sys.executable, str(ROOT / "reference" / "python" / "xi_partner_r14_evidence.py"),
                "--archive", str(archive_path), "--expected-sha256", digest(raw),
                "--peer-public-key-base64", base64.b64encode(public).decode(),
                "--transport-spec", str(transport_path), "--native-schema", str(schema_path),
            ]
            ordinary = subprocess.run(args, text=True, capture_output=True, timeout=20)
            self.assertEqual(ordinary.returncode, 0, ordinary.stderr[-400:])
            report = json.loads(ordinary.stdout)
            self.assertFalse(report["safe_to_enable_live_bridge"])
            strict = subprocess.run(args + ["--require-live"],
                                    text=True, capture_output=True, timeout=20)
            self.assertEqual(strict.returncode, 2)
            self.assertEqual(json.loads(strict.stdout)["status"],
                             "R14_FIXTURE_INTEGRITY_VERIFIED_INDEPENDENT_EVIDENCE_HOLD")


if __name__ == "__main__":
    unittest.main()
