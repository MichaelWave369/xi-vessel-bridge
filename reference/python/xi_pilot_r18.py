#!/usr/bin/env python3
"""R18 local synthetic capsule and pilot preflight; no remote transport.

This tool cannot approve a real Xi peer or convert self-reported pilot fields
into independent security evidence. It never connects to a network.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

FIXTURE_SCHEMA = "PhiXi.R18SyntheticFixture.v1"
PREFLIGHT_SCHEMA = "PhiXi.R18PilotDraft.v1"
TRANSCRIPT_SCHEMA = "PhiXi.R18TranscriptCandidate.v1"
PAYLOAD = b"PHI-XI R18 SYNTHETIC DIGEST FIXTURE v1\nNO PRIVATE DATA; NO AUTHORITY; NO REMOTE RIGHTS.\n"
PURPOSE = "digest-only offline operator rehearsal"
MAX_DOCUMENT = 32 * 1024
MAX_PAYLOAD = 4096
HEX = re.compile(r"^[0-9a-f]{64}$")
FIXTURE_FIELDS = {"schema", "payload_b64", "size_bytes", "sha256", "origin",
                  "intended_use", "classification", "authority", "live_xi_connected"}
PREFLIGHT_FIELDS = {
    "schema", "status", "transport", "endpoint_reference", "native_schema_sha256",
    "xi_peer_pin", "phi_peer_pin", "phi_operator_approval", "xi_operator_approval",
    "transport_security_verified", "provenance_verified", "durable_receipts_verified",
    "independent_revocation_verified", "data_classification", "scope",
    "live_xi_connected", "authority"
}
TRANSCRIPT_FIELDS = {"schema", "fixture_sha256", "phi_observed_sha256",
                     "xi_observed_sha256", "phi_receipt_reference", "xi_receipt_reference",
                     "two_physical_hosts_confirmed", "notes", "status"}


class Refused(ValueError):
    pass


def check(value, reason):
    if not value:
        raise Refused(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    path = Path(path)
    check(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_DOCUMENT,
          "missing, symlinked or oversized input")
    return json.loads(path.read_text(encoding="utf-8"))


def fixture():
    return {
        "schema": FIXTURE_SCHEMA, "payload_b64": base64.b64encode(PAYLOAD).decode("ascii"),
        "size_bytes": len(PAYLOAD), "sha256": sha(PAYLOAD),
        "origin": "PHI369-local-synthetic-fixture",
        "intended_use": PURPOSE, "classification": "synthetic_public",
        "authority": "none", "live_xi_connected": False
    }


def verify_fixture(doc):
    check(isinstance(doc, dict) and set(doc) == FIXTURE_FIELDS, "fixture fields mismatch")
    check(doc["schema"] == FIXTURE_SCHEMA and doc["origin"] == "PHI369-local-synthetic-fixture"
          and doc["intended_use"] == PURPOSE and doc["classification"] == "synthetic_public"
          and doc["authority"] == "none" and doc["live_xi_connected"] is False,
          "fixture provenance or authority mismatch")
    raw = doc["payload_b64"]
    check(isinstance(raw, str) and len(raw) <= MAX_PAYLOAD * 2, "encoded payload too large")
    try:
        blob = base64.b64decode(raw, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refused("noncanonical base64 input") from exc
    check(blob == PAYLOAD and type(doc["size_bytes"]) is int and
          doc["size_bytes"] == len(blob) and doc["sha256"] == sha(blob),
          "synthetic payload bytes or hash mismatch")
    return {"status": "OFFLINE_SYNTHETIC_FIXTURE_VERIFIED", "sha256": sha(blob),
            "size_bytes": len(blob), "real_xi_receipts": 0,
            "live_xi_connected": False, "authority": "none"}


def draft():
    return {
        "schema": PREFLIGHT_SCHEMA,
        "status": "draft_no_approval", "transport": "unconfigured",
        "endpoint_reference": None, "native_schema_sha256": None,
        "xi_peer_pin": None, "phi_peer_pin": None,
        "phi_operator_approval": False, "xi_operator_approval": False,
        "transport_security_verified": False, "provenance_verified": False,
        "durable_receipts_verified": False, "independent_revocation_verified": False,
        "data_classification": "synthetic_public", "scope": "digest_only",
        "live_xi_connected": False, "authority": "none"
    }


def inspect_preflight(doc):
    check(isinstance(doc, dict) and set(doc) == PREFLIGHT_FIELDS, "preflight fields mismatch")
    check(doc["schema"] == PREFLIGHT_SCHEMA and doc["status"] == "draft_no_approval",
          "pilot draft cannot claim approved status")
    check(doc["scope"] == "digest_only" and doc["data_classification"] == "synthetic_public",
          "pilot data scope cannot be broadened")
    check(doc["live_xi_connected"] is False and doc["authority"] == "none",
          "preflight JSON cannot confer a live bridge")
    conditions = {
        "independently verified Xi peer key": doc["xi_peer_pin"] is None,
        "independently verified PHI peer key": doc["phi_peer_pin"] is None,
        "native Xi schema pin": doc["native_schema_sha256"] is None,
        "approved endpoint description": doc["endpoint_reference"] is None,
        "authenticated encrypted transport": doc["transport_security_verified"] is False,
        "PHI human scope approval": doc["phi_operator_approval"] is False,
        "Xi human scope approval": doc["xi_operator_approval"] is False,
        "provenance verification": doc["provenance_verified"] is False,
        "independent receipt verification": doc["durable_receipts_verified"] is False,
        "revoke/disconnect evidence": doc["independent_revocation_verified"] is False,
    }
    check(all(type(doc[key]) is bool for key in (
        "phi_operator_approval", "xi_operator_approval", "transport_security_verified",
        "provenance_verified", "durable_receipts_verified", "independent_revocation_verified"
    )), "approval flags must be actual booleans")
    check(doc["transport"] == "unconfigured", "pilot transport cannot be declared active here")
    # Even if fields are filled, there is no verifier of independent evidence in this
    # static draft. Label every non-null or positive claim 'unverified' and stay BLOCKED.
    for k in ("xi_peer_pin", "phi_peer_pin", "native_schema_sha256", "endpoint_reference"):
        if doc[k] is not None:
            check(isinstance(doc[k], str) and len(doc[k]) <= 512 and len(doc[k]) > 0,
                  "invalid evidence candidate field: " + k)
    outstanding = [
        label for label, absent in conditions.items() if absent
    ]
    candidates = [
        label for label, absent in conditions.items() if not absent
    ]
    return {
        "pilot_status": "BLOCKED_PENDING_INDEPENDENT_PROOF",
        "missing_claims": outstanding, "self_reported_unverified_claims": candidates,
        "independently_verified_gates": 0, "live_xi_connected": False,
        "authority": "none", "next_step": "Review real external evidence with both operators and a separate trusted verifier, never with this draft."
    }


def empty_transcript():
    return {
        "schema": TRANSCRIPT_SCHEMA, "fixture_sha256": sha(PAYLOAD),
        "phi_observed_sha256": None, "xi_observed_sha256": None,
        "phi_receipt_reference": None, "xi_receipt_reference": None,
        "two_physical_hosts_confirmed": False,
        "notes": "No real two-host pilot performed", "status": "not_run"
    }


def inspect_transcript(doc):
    check(isinstance(doc, dict) and set(doc) == TRANSCRIPT_FIELDS, "transcript fields mismatch")
    check(doc["schema"] == TRANSCRIPT_SCHEMA and doc["fixture_sha256"] == sha(PAYLOAD),
          "wrong synthetic fixture")
    check(doc["status"] in ("not_run", "candidate_unverified"), "unsupported transcript status")
    check(type(doc["two_physical_hosts_confirmed"]) is bool, "boolean required")
    check(isinstance(doc["notes"], str) and len(doc["notes"]) <= 800, "invalid notes")
    for key in ("phi_observed_sha256", "xi_observed_sha256"):
        item = doc[key]
        check(item is None or (isinstance(item, str) and HEX.fullmatch(item)),
              "invalid reported digest")
    for key in ("phi_receipt_reference", "xi_receipt_reference"):
        item = doc[key]
        check(item is None or (isinstance(item, str) and 0 < len(item) <= 256),
              "invalid receipt reference")
    if doc["status"] == "not_run":
        check(not doc["two_physical_hosts_confirmed"] and all(
              doc[key] is None for key in (
                  "phi_observed_sha256", "xi_observed_sha256",
                  "phi_receipt_reference", "xi_receipt_reference")),
              "not-run transcript cannot assert observations")
    reported_match = (doc["phi_observed_sha256"] == sha(PAYLOAD)
                      and doc["xi_observed_sha256"] == sha(PAYLOAD))
    return {
        "status": "CANDIDATE_SELF_REPORT_ONLY" if doc["status"] != "not_run" else "NOT_RUN",
        "self_reported_digest_match": reported_match,
        "independently_authenticated_receipts": 0,
        "two_host_connection_verified": False, "live_xi_connected": False,
        "authority": "none"
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("fixture")
    for command in ("verify-fixture", "preflight", "inspect-transcript"):
        sub.add_parser(command).add_argument("--file", type=Path, required=True)
    sub.add_parser("draft")
    sub.add_parser("transcript-template")
    sub.add_parser("require-live")
    args = p.parse_args(argv)
    try:
        if args.action == "fixture":
            result = fixture()
        elif args.action == "verify-fixture":
            result = verify_fixture(read(args.file))
        elif args.action == "draft":
            result = draft()
        elif args.action == "preflight":
            result = inspect_preflight(read(args.file))
        elif args.action == "transcript-template":
            result = empty_transcript()
        elif args.action == "inspect-transcript":
            result = inspect_transcript(read(args.file))
        else:
            result = inspect_preflight(draft())
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.action == "require-live":
            print("REFUSED: R18 offline preflight is not independent live authorization", file=sys.stderr)
            return 2
        return 0
    except (Refused, OSError, ValueError, UnicodeError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc),
                          "live_xi_connected": False, "authority": "none"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
