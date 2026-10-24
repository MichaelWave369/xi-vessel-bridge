#!/usr/bin/env python3
"""R14: require actual public evidence bytes, not substring-based defect counts.

Offline, no partner-code execution, network, credentials, archive extraction,
review signing or grant creation. Even perfect public digests never prove
operator identity, durable replay prevention or live transport.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path

from xi_partner_r13_intake import IntakeError, inspect_archive

MAX_FILE = 262_144
CONTRACT = "xi_partner_r10_staging_candidate.json"
REVIEW = "xi_partner_r11_bundle.json"
RUNNER = "xi_mikey_r10_r11_r12_conformance_runner.py"
NEEDED_FILES = {CONTRACT, REVIEW, RUNNER}


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verified_members(raw: bytes, expected_sha256: str) -> tuple[dict, dict[str, bytes]]:
    """Only inspect allowlisted members after the R13 full integrity gate."""
    gate = inspect_archive(raw, expected_sha256)
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as pack:
        for member in pack:
            name = member.name[2:] if member.name.startswith("./") else member.name
            if name in NEEDED_FILES:
                files[name] = pack.extractfile(member).read()
    if set(files) != NEEDED_FILES:
        raise IntakeError("required_evidence_members_missing")
    return gate, files


def decode_public_key_base64(value: str) -> bytes:
    if not isinstance(value, str) or len(value) != 44:
        raise IntakeError("public_key_b64_invalid")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IntakeError("public_key_b64_invalid") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise IntakeError("public_key_raw_ed25519_required")
    return raw


def review_public_evidence(raw: bytes, expected_sha256: str, *,
                           public_key: bytes | None = None,
                           transport_spec: bytes | None = None,
                           native_schema: bytes | None = None) -> dict:
    r13, docs = verified_members(raw, expected_sha256)
    contract = json.loads(docs[CONTRACT])
    review = json.loads(docs[REVIEW])
    source = docs[RUNNER].decode("utf-8", "replace")
    evidence = contract["evidence"]
    wire = contract["wire"]
    checks: dict[str, dict] = {}
    blockers = []

    expected_pin = evidence["out_of_band_peer_signing_key_sha256"]
    if public_key is None:
        checks["peer_public_key"] = {"status": "MISSING_BYTES", "expected_sha256": expected_pin}
        blockers.append("PEER_PUBLIC_KEY_BYTES_NOT_IN_PARTNER_ARCHIVE")
    elif type(public_key) is not bytes or len(public_key) != 32:
        raise IntakeError("public_key_raw_ed25519_required")
    else:
        measured = sha256(public_key)
        checks["peer_public_key"] = {
            "status": "HASH_MATCH_UNAUTHENTICATED" if measured == expected_pin else "HASH_MISMATCH",
            "expected_sha256": expected_pin, "measured_sha256": measured,
        }
        if measured != expected_pin:
            blockers.append("PEER_PUBLIC_KEY_HASH_MISMATCH")

    for label, supplied, expected in (
        ("xi_transport_spec", transport_spec, evidence["official_transport_doc_sha256"]),
        ("xi_native_schema", native_schema, wire["native_schema_sha256"]),
    ):
        if supplied is None:
            checks[label] = {"status": "MISSING_BYTES", "expected_sha256": expected}
            blockers.append(label.upper() + "_BYTES_NOT_SUPPLIED")
        elif type(supplied) is not bytes or not 0 < len(supplied) <= MAX_FILE:
            raise IntakeError(label + "_size_invalid")
        else:
            measured = sha256(supplied)
            checks[label] = {
                "status": "HASH_MATCH_UNAUTHENTICATED" if measured == expected else "HASH_MISMATCH",
                "expected_sha256": expected, "measured_sha256": measured,
            }
            if measured != expected:
                blockers.append(label.upper() + "_HASH_MISMATCH")

    # Signed on someone else's host is not the Phi operator's approval.
    # Even a valid Ed25519 signature doesn't establish custody of the key.
    if "phi_reviewer" in review["attestations"]:
        blockers.append("PARTNER_ARCHIVE_CONTAINS_PRE_SIGNED_PHI_REVIEWER_SLOT")
    if review["pins"]["origin"] == "synthetic_self_issued":
        blockers.append("REVIEW_PINS_EXPLICITLY_SELF_ISSUED")
    if review["verification"].get("keys_independently_authenticated") is not True:
        blockers.append("REVIEWER_IDENTITY_NOT_INDEPENDENTLY_AUTHENTICATED")

    # Static clues are supplementary. Their absence MUST NOT promote a bundle.
    static_clues = []
    if ("Ed25519PrivateKey.from_private_bytes(hashlib.sha256(domain_tag).digest())" in source
            and "phi.fixture.placeholder" in source):
        static_clues.append("DETERMINISTIC_PHI_FIXTURE_SIGNER_IN_RUNNER")
    if "tempfile.TemporaryDirectory()" in source and "sqlite3.connect(db_path" in source:
        static_clues.append("TEST_DATABASE_IS_TEMPORARY_FILE_NOT_RESTART_PROOF")

    # No report here can certify independent peer identity, operator grant,
    # a true process restart/replay test, or authenticated deployed transport.
    blockers.extend((
        "PEER_IDENTITY_OUT_OF_BAND_UNVERIFIED",
        "PHI_OPERATOR_REVIEW_AND_EXPLICIT_APPROVAL_UNVERIFIED",
        "DURABLE_RESTART_AND_REPLAY_CHALLENGE_NOT_WITNESSED",
        "SCOPED_GRANT_AND_REVOCATION_NOT_WITNESSED",
        "LIVE_XI_TRANSPORT_NOT_WITNESSED",
    ))

    return {
        "format": "xi.phi.public-evidence-review.r14",
        "status": "R14_FIXTURE_INTEGRITY_VERIFIED_INDEPENDENT_EVIDENCE_HOLD",
        "archive_sha256": expected_sha256,
        "archive_file_pins_matched": r13["archive_file_pins_matched"],
        "r13_status": r13["status"],
        "r10_contract_sha256": review["request"]["contract_sha256"],
        "r12_self_reported_matches": r13["r12_self_reported_matches"],
        "declared_scopes": contract["authorization"]["scopes"],
        "reply_endpoint_declared": contract["transport"]["reply_url"] is not None,
        "public_artifact_checks": checks,
        "static_source_clues": sorted(static_clues),
        "blocking_findings": sorted(set(blockers)),
        "public_bytes_hashes_prove_identity": False,
        "independent_phi_review_verified": False,
        "durable_runtime_verified": False,
        "live_xi_connected": False,
        "safe_to_enable_live_bridge": False,
    }


def read_local(path: str | None, *, maximum=MAX_FILE) -> bytes | None:
    if path is None:
        return None
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.stat().st_size > maximum:
        raise IntakeError("public_evidence_file_invalid")
    return target.read_bytes()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True, help="Untrusted archive; NEVER executed")
    p.add_argument("--expected-sha256", required=True, help="Exact outer sha256, not identity")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--peer-public-key-base64", help="PUBLIC Ed25519 32-byte raw key only")
    group.add_argument("--peer-public-key-raw-file", help="Local PUBLIC Ed25519 raw 32-byte file")
    p.add_argument("--transport-spec", help="Actual public Xi-owned transport spec bytes")
    p.add_argument("--native-schema", help="Actual public Xi-owned native schema bytes")
    p.add_argument("--require-live", action="store_true", help="Fail closed: no live evidence in offline bundles")
    args = p.parse_args(argv)
    try:
        raw = read_local(args.archive, maximum=65_536)
        if raw is None:
            raise IntakeError("archive_file_unavailable")
        key = (decode_public_key_base64(args.peer_public_key_base64)
               if args.peer_public_key_base64 else
               read_local(args.peer_public_key_raw_file, maximum=32))
        report = review_public_evidence(
            raw, args.expected_sha256,
            public_key=key,
            transport_spec=read_local(args.transport_spec),
            native_schema=read_local(args.native_schema),
        )
    except (IntakeError, OSError, ValueError, TypeError, KeyError, tarfile.TarError) as exc:
        # Deliberately don't echo untrusted exception text other than our own known IntakeError.
        reason = str(exc) if isinstance(exc, IntakeError) else "invalid_evidence_input"
        print(json.dumps({"status": "R14_UNTRUSTED_EVIDENCE_REJECTED", "reason": reason},
                         sort_keys=True))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if args.require_live else 0


if __name__ == "__main__":
    sys.exit(main())
