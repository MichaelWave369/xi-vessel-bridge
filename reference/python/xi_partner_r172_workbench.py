#!/usr/bin/env python3
"""R17.2 PHI-side review of supplied Xi candidate files.

Purely offline intake. Strictly checks shapes and self-reported statements using
the prior R17.1/R18 validators; never authenticates a Xi peer, contacts any
endpoint, stores input, or grants access. Output intentionally excludes partner
free text, endpoints, keys, and untrusted field values.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import xi_capability_r171 as cap
import xi_pilot_r18 as pilot

SCHEMA = "PhiXi.PartnerIntakeReview.R17_2.v1"
MAX_INPUT = 128 * 1024
SLOTS = tuple(f"xi-preview-{n:02d}" for n in range(1, 14))


class Refused(ValueError):
    pass


def strict_read(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise Refused("input must be an ordinary bounded file")
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT:
        raise Refused("input exceeded size limit")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Refused("input is not UTF-8 JSON") from exc
    return parsed, hashlib.sha256(raw).hexdigest()


def review(registry, response=None, preflight=None, transcript=None):
    """All values are parsed dictionaries; return a deliberately redacted report."""
    cap.validate_registry(registry)
    report = {
        "schema": SCHEMA, "stage": "R17.2", "verdict": "BLOCKED_PENDING_EXTERNAL_EVIDENCE",
        "registry_sha256": cap.document_hash(registry),
        "candidate_slots": [],
        "unmapped_slots": list(SLOTS),
        "file_reviews": {},
        "required_independent_evidence": [
            "out-of-band verification of Xi and PHI identity public keys",
            "exact source-backed Xi native schema bytes and transport contract",
            "explicit independent approvals from both human operators",
            "authenticated encrypted two-host transport and scoped data consent",
            "signed, independently verified runtime receipts and restart replay tests",
            "unilateral pause, revocation and reconnection tests on both machines"
        ],
        "claims_not_established": ["live_xi_connected", "peer_authenticated",
                                   "human_authorization", "external_two_host_test"],
        "independently_verified_partner_capabilities": 0,
        "authorized_operations": 0,
        "live_xi_connected": False, "authority": "none",
        "disclosure": "Self-reported candidate syntax is not peer identity, consent, or real execution evidence."
    }
    if response is not None:
        info = cap.validate_response(response, registry)
        mapped = [record["slot_id"] for record in response["records"]]
        report["candidate_slots"] = sorted(mapped)
        report["unmapped_slots"] = info["still_unmapped"]
        report["file_reviews"]["partner_response"] = {
            "state": "SELF_REPORTED_CANDIDATES_ONLY",
            "candidate_count": len(mapped),
            "independent_proof_count": 0, "authorization_count": 0
        }
    else:
        report["file_reviews"]["partner_response"] = {
            "state": "NOT_SUPPLIED", "candidate_count": 0
        }
    if preflight is not None:
        info = pilot.inspect_preflight(preflight)
        report["file_reviews"]["pilot_preflight"] = {
            "state": "BLOCKED_PENDING_INDEPENDENT_PROOF",
            "missing_claim_count": len(info["missing_claims"]),
            "unverified_candidate_claim_count": len(info["self_reported_unverified_claims"]),
            "independent_proof_count": 0
        }
    else:
        report["file_reviews"]["pilot_preflight"] = {"state": "NOT_SUPPLIED"}
    if transcript is not None:
        info = pilot.inspect_transcript(transcript)
        report["file_reviews"]["pilot_transcript"] = {
            "state": info["status"],
            "self_reported_digest_match": info["self_reported_digest_match"],
            "independently_authenticated_receipts": 0
        }
    else:
        report["file_reviews"]["pilot_transcript"] = {"state": "NOT_SUPPLIED"}
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=Path(__file__).resolve().parents[2] /
                        "roadmap" / "capability-registry.json")
    parser.add_argument("--response", type=Path)
    parser.add_argument("--preflight", type=Path)
    parser.add_argument("--transcript", type=Path)
    parser.add_argument("--require-live", action="store_true",
                        help="Always refuse: static intake cannot certify external partner authority")
    args = parser.parse_args(argv)
    try:
        inputs = {
            "registry": strict_read(args.registry),
            "partner_response": strict_read(args.response) if args.response else None,
            "pilot_preflight": strict_read(args.preflight) if args.preflight else None,
            "pilot_transcript": strict_read(args.transcript) if args.transcript else None
        }
        result = review(
            inputs["registry"][0],
            response=inputs["partner_response"][0] if inputs["partner_response"] else None,
            preflight=inputs["pilot_preflight"][0] if inputs["pilot_preflight"] else None,
            transcript=inputs["pilot_transcript"][0] if inputs["pilot_transcript"] else None
        )
        result["input_sha256"] = {
            name: filedata[1] for name, filedata in inputs.items() if filedata is not None
        }
        print(json.dumps(result, sort_keys=True, indent=2))
        if args.require_live:
            print("R17_2_REFUSED: candidate review cannot certify a live Xi crossing", file=sys.stderr)
            return 2
        return 0
    except (Refused, cap.Refused, pilot.Refused, OSError, UnicodeError, ValueError) as exc:
        # Never echo a received value or file contents back in error diagnostics.
        print(json.dumps({"schema": SCHEMA, "verdict": "INVALID_INPUT_REFUSED",
                          "reason": type(exc).__name__, "live_xi_connected": False,
                          "authority": "none"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
