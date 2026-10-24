#!/usr/bin/env python3
"""R13: inspect a partner R10/R11/R12 handoff archive without executing it.

Digest agreement protects against unintended byte changes, NOT against a
dishonest packager. Valid R10/R11/R12 results are still non-operational.
No network, credentials, tar extraction, dynamic imports or partner execution.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

from xi_partner_r10 import validate as validate_r10
from xi_partner_r11 import verify as verify_r11
from xi_partner_r12 import assess as assess_r12

MAX_ARCHIVE_BYTES = 65_536
MAX_TOTAL_BYTES = 200_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PIN_FILES = frozenset({
    "r12_interop/response-template.json",
    "r12_interop/suite.json",
    "r12_interop/synthetic-example-response.json",
    "xi_mikey_r10_r11_r12_conformance_runner.py",
    "xi_partner_r10_inspection.json",
    "xi_partner_r10_staging_candidate.json",
    "xi_partner_r11_bundle.json",
    "xi_partner_r12_assessment.json",
    "xi_partner_r12_response.json",
})
ALL_FILES = PIN_FILES | {"README_PINS.json"}


class IntakeError(ValueError):
    pass


def _no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise IntakeError("duplicate_json_key")
        obj[key] = value
    return obj


def _json(raw: bytes, name: str) -> dict:
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             IntakeError("invalid_json_number")))
        if not isinstance(obj, dict):
            raise IntakeError("expected_object:" + name)
        return obj
    except (UnicodeError, ValueError, TypeError) as exc:
        if isinstance(exc, IntakeError):
            raise
        raise IntakeError("invalid_json:" + name) from exc


def inspect_archive(raw: bytes, expected_sha256: str) -> dict:
    """Inspect an externally supplied bundle with no archive member extraction.

    SHA-256 must be supplied by the operator. The digest's *source* is
    not authenticated; even a successful checksum is NOT partner identity.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ARCHIVE_BYTES:
        raise IntakeError("archive_size_invalid")
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise IntakeError("expected_digest_invalid")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_sha256:
        raise IntakeError("archive_digest_mismatch")

    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as pack:
            for entry in pack:
                name = entry.name
                if name.startswith("./"):
                    name = name[2:]
                if entry.isdir() and name in {".", "", "r12_interop"}:
                    continue
                if not entry.isfile() or name not in ALL_FILES or name in files:
                    raise IntakeError("unsafe_or_unknown_archive_member")
                if entry.size < 0 or entry.size > MAX_TOTAL_BYTES:
                    raise IntakeError("member_size_invalid")
                total += entry.size
                if total > MAX_TOTAL_BYTES:
                    raise IntakeError("archive_unpacked_size_exceeded")
                member = pack.extractfile(entry)
                if member is None:
                    raise IntakeError("archive_member_unreadable")
                data = member.read(entry.size + 1)
                if len(data) != entry.size:
                    raise IntakeError("archive_member_size_mismatch")
                files[name] = data
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise IntakeError("archive_invalid") from exc
    if set(files) != ALL_FILES:
        raise IntakeError("archive_required_files_missing")

    pins = _json(files["README_PINS.json"], "README_PINS.json")
    if set(pins) != {"package", "files"} or not isinstance(pins["files"], dict):
        raise IntakeError("pin_manifest_invalid")
    if set(pins["files"]) != PIN_FILES:
        raise IntakeError("pin_manifest_file_set_invalid")
    for name in sorted(PIN_FILES):
        pin = pins["files"][name]
        if not isinstance(pin, dict) or set(pin) != {"size_bytes", "sha256"}:
            raise IntakeError("pin_entry_invalid")
        if type(pin["size_bytes"]) is not int or pin["size_bytes"] != len(files[name]):
            raise IntakeError("pin_size_mismatch:" + name)
        if pin["sha256"] != hashlib.sha256(files[name]).hexdigest():
            raise IntakeError("pin_digest_mismatch:" + name)

    candidate = _json(files["xi_partner_r10_staging_candidate.json"], "r10_contract")
    r10_claim = _json(files["xi_partner_r10_inspection.json"], "r10_report")
    try:
        r10_measured = validate_r10(candidate)
    except (ValueError, TypeError, KeyError) as exc:
        raise IntakeError("r10_candidate_invalid") from exc
    if r10_measured != r10_claim:
        raise IntakeError("r10_report_inconsistent")

    suite = _json(files["r12_interop/suite.json"], "r12_suite")
    response = _json(files["xi_partner_r12_response.json"], "r12_response")
    r12_claim = _json(files["xi_partner_r12_assessment.json"], "r12_report")
    try:
        r12_measured = assess_r12(suite, response)
    except (ValueError, TypeError, KeyError) as exc:
        raise IntakeError("r12_response_invalid") from exc
    if r12_measured != r12_claim:
        raise IntakeError("r12_report_inconsistent")

    r11 = _json(files["xi_partner_r11_bundle.json"], "r11_bundle")
    if set(r11) != {"request", "attestations", "pins", "verification"}:
        raise IntakeError("r11_bundle_invalid")
    try:
        # Historical signature check only: it MUST NOT confer current validity.
        historic_time = r11["request"]["issued_at"] + 1
        r11_measured = verify_r11(candidate, r11["request"],
                                  r11["attestations"], r11["pins"],
                                  now=historic_time)
    except (ValueError, TypeError, KeyError) as exc:
        raise IntakeError("r11_review_invalid") from exc
    if r11_measured != r11["verification"]:
        raise IntakeError("r11_report_inconsistent")

    # Additional defects cannot be erased by checksum agreement.
    findings = [
        "R12_PARTNER_SELF_REPORT_NOT_DEPLOYED_TRANSPORT_EVIDENCE",
        "R11_REVIEW_SIG_VALID_AT_ISSUE_TIME_NOT_INDEPENDENT_APPROVAL",
        "R10_COMPLETE_SHAPE_NOT_AUTHENTICATED_CONTRACT",
        "INDEPENDENT_PEER_KEY_AND_NATIVE_WIRE_SPEC_STILL_REQUIRED",
        "OPERATOR_CONTROLLED_GRANT_AND_REAL_TRANSPORT_RECEIPT_STILL_REQUIRED",
    ]
    key_digest = candidate["evidence"]["out_of_band_peer_signing_key_sha256"]
    revocation_digest = candidate["authorization"]["revocation_spec_sha256"]
    if key_digest == revocation_digest:
        findings.append("R10_PEER_KEY_PIN_REUSES_REVOCATION_SPEC_DIGEST")
    runner = files["xi_mikey_r10_r11_r12_conformance_runner.py"].decode("utf-8", "replace")
    if ("xi_rev_key = Ed25519PrivateKey.generate()" in runner
            and "phi_rev_key = Ed25519PrivateKey.generate()" in runner):
        findings.append("R11_SUPPLIED_RUNNER_SELF_GENERATES_BOTH_REVIEW_KEYS")
    if 'sqlite3.connect(":memory:")' in runner:
        findings.append("R12_SUPPLIED_RUNNER_USES_IN_MEMORY_SQLITE_ADAPTER")
    own_doc = Path(__file__).resolve().parents[2] / "docs" / "HUNTER_TABLE_HANDOFF.md"
    if own_doc.is_file() and hashlib.sha256(own_doc.read_bytes()).hexdigest() == candidate["evidence"]["official_transport_doc_sha256"]:
        findings.append("R10_OFFICIAL_DOC_PIN_POINTS_TO_PHI_HANDOFF_NOT_INDEPENDENT_XI_SPEC")
    own_schema = Path(__file__).resolve().parents[2] / "spec" / "xi.exchange.v1.schema.json"
    if own_schema.is_file() and hashlib.sha256(own_schema.read_bytes()).hexdigest() == candidate["wire"]["native_schema_sha256"]:
        findings.append("R10_NATIVE_SCHEMA_PIN_POINTS_TO_PHI_EXCHANGE_SCHEMA")

    return {
        "format": "xi.phi.partner-archive-triage.r13",
        "status": "R13_VERIFIED_BYTES_FIXTURE_ONLY_LIVE_BLOCKED",
        "archive_sha256": actual,
        "archive_file_pins_matched": len(PIN_FILES),
        "archive_source_authenticated": False,
        "r10_status": r10_measured["status"],
        "r11_status": r11_measured["status"],
        "r11_verified_at": "historical_request_time_only",
        "r11_request_expires_at_epoch": r11["request"]["expires_at"],
        "r12_status": r12_measured["status"],
        "r12_self_reported_matches": r12_measured["self_reported_matches"],
        "r12_self_reported_mismatches": r12_measured["self_reported_mismatches"],
        "live_transport_verified": False,
        "peer_identity_authenticated": False,
        "operator_grant_verified": False,
        "safe_to_enable_live_bridge": False,
        "blocking_findings": sorted(findings),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, help="Untrusted tar.gz handoff; never executed")
    parser.add_argument("--expected-sha256", required=True,
                        help="Exact out-of-band checksum (not identity verification)")
    parser.add_argument("--require-live", action="store_true",
                        help="Fail closed (this tool NEVER certifies live transport)")
    args = parser.parse_args(argv)
    try:
        p = Path(args.archive)
        if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_ARCHIVE_BYTES:
            raise IntakeError("archive_file_unavailable")
        result = inspect_archive(p.read_bytes(), args.expected_sha256)
    except (IntakeError, OSError) as exc:
        print(json.dumps({"status": "R13_UNTRUSTED_ARCHIVE_REJECTED", "reason": str(exc)},
                         sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if args.require_live else 0


if __name__ == "__main__":
    sys.exit(main())
