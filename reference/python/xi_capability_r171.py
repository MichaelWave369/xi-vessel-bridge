#!/usr/bin/env python3
"""R17.1 candidate registry and Xi partner response intake, offline only.

Public showcase counts are not live capabilities. This tool never authenticates
a remote peer, promotes a field to a grant, contacts Xi, or writes credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

REGISTRY_SCHEMA = "PhiXi.CapabilityRegistry.Candidate.v1"
RESPONSE_SCHEMA = "PhiXi.PartnerCapabilityResponse.Candidate.v1"
REQUEST_SCHEMA = "PhiXi.PartnerCapabilityRequest.v1"
ROOT_FIELDS = {"schema", "snapshot_date", "status", "source_url", "public_advertised_count",
               "live_xi_connected", "authority", "auto_grants", "disclosure", "xi_slots",
               "phi_candidates", "partner_request"}
SLOT_FIELDS = {"slot_id", "public_name", "native_operation", "schema_sha256", "endpoint_id",
               "independently_verified", "authorized", "state", "source"}
PHI_FIELDS = {"id", "name", "scope", "read_only", "exposed_remotely", "source"}
RESPONSE_FIELDS = {"schema", "reply_to_registry_sha256", "records", "statement"}
RECORD_FIELDS = {"slot_id", "name", "operation", "schema_sha256",
                 "endpoint_description", "evidence_url", "source_author"}
REQUEST_FIELDS = {"requested_information", "recipient", "note"}
EXPECTED_PHI = {"phi.artifact.sha256", "phi.porch.inventory", "phi.handshake.observe"}
EXPECTED_SLOT_IDS = [f"xi-preview-{i:02d}" for i in range(1, 14)]
HEX = re.compile(r"^[a-f0-9]{64}$")
MAX_DOC = 128 * 1024


class Refused(ValueError):
    pass


def check(condition, reason):
    if not condition:
        raise Refused(reason)


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def document_hash(data):
    return hashlib.sha256(canonical(data)).hexdigest()


def read_json(path):
    path = Path(path)
    check(not path.is_symlink() and path.is_file(), "untrusted or absent input file")
    check(path.stat().st_size <= MAX_DOC, "input exceeds document byte limit")
    return json.loads(path.read_text(encoding="utf-8"))


def bounded(value, label, maximum=240):
    check(isinstance(value, str) and 0 < len(value) <= maximum and
          all(ord(ch) >= 32 for ch in value), "missing, invalid or overlong " + label)
    return value


def source_url(value):
    bounded(value, "source URL", 1024)
    parts = urlparse(value)
    check(parts.scheme == "https" and not parts.username and not parts.password and
          parts.hostname in ("www.xi-field.com", "xi-field.com", "github.com", "room.xi-field.com"),
          "source URL not in explicitly documented host scope")
    return value


def validate_registry(reg):
    check(isinstance(reg, dict) and set(reg) == ROOT_FIELDS, "registry fields mismatch")
    check(reg["schema"] == REGISTRY_SCHEMA, "schema mismatch")
    check(reg["snapshot_date"] == "2026-10-25", "source date requires re-review")
    check(reg["status"] == "unmapped_public_preview", "promoted registry status")
    source_url(reg["source_url"])
    check(type(reg["public_advertised_count"]) is int and reg["public_advertised_count"] == 13,
          "public count is not an identity roster")
    check(reg["live_xi_connected"] is False and reg["authority"] == "none" and
          reg["auto_grants"] is False, "registry cannot confer authority")
    bounded(reg["disclosure"], "disclosure", 1024)
    slots = reg["xi_slots"]
    check(isinstance(slots, list) and len(slots) == 13, "expected 13 anonymous preview slots")
    for slot, expected in zip(slots, EXPECTED_SLOT_IDS):
        check(isinstance(slot, dict) and set(slot) == SLOT_FIELDS, "slot fields mismatch")
        check(slot["slot_id"] == expected, "duplicate or reordered preview slot")
        check(all(slot[key] is None for key in ("public_name", "native_operation",
                                               "schema_sha256", "endpoint_id")),
              "anonymous slot cannot be silently assigned an operation")
        check(slot["independently_verified"] is False and slot["authorized"] is False and
              slot["state"] == "awaiting_partner_spec" and slot["source"] == "public_count_only",
              "slot has unsupported live evidence claim")
    phi = reg["phi_candidates"]
    check(isinstance(phi, list) and len(phi) == 3, "unexpected local candidate roster")
    check({x.get("id") for x in phi if isinstance(x, dict)} == EXPECTED_PHI,
          "unexpected local candidate identity")
    for x in phi:
        check(isinstance(x, dict) and set(x) == PHI_FIELDS, "local candidate fields mismatch")
        bounded(x["name"], "local candidate name")
        bounded(x["scope"], "local candidate scope")
        check(x["read_only"] is True and x["exposed_remotely"] is False,
              "fixture is not remotely exposed")
        source_url(x["source"])
    request = reg["partner_request"]
    check(isinstance(request, dict) and set(request) == REQUEST_FIELDS, "partner request mismatch")
    check(isinstance(request["requested_information"], list) and
          len(request["requested_information"]) >= 6, "insufficient contract questions")
    for item in request["requested_information"]:
        bounded(item, "contract question", 1024)
    bounded(request["recipient"], "recipient")
    bounded(request["note"], "request note", 1024)
    return reg


def make_request(reg):
    validate_registry(reg)
    return {
        "schema": REQUEST_SCHEMA,
        "registry_sha256": document_hash(reg),
        "source_date": reg["snapshot_date"],
        "slots": list(EXPECTED_SLOT_IDS),
        "questions": reg["partner_request"]["requested_information"],
        "reply_contract": RESPONSE_SCHEMA,
        "allow_credentials": False,
        "authorization_from_response": False,
        "live_xi_connected": False,
        "message": "Please identify supported public preview items with source-linked native schemas; no secrets, claims of permission or endpoint credentials."
    }


def validate_response(response, reg):
    validate_registry(reg)
    check(isinstance(response, dict) and set(response) == RESPONSE_FIELDS,
          "partner response envelope invalid or contains forbidden fields")
    check(response["schema"] == RESPONSE_SCHEMA and
          response["reply_to_registry_sha256"] == document_hash(reg),
          "reply bound to wrong registry version")
    bounded(response["statement"], "response statement", 1024)
    records = response["records"]
    check(isinstance(records, list) and len(records) <= 13, "response record count")
    seen = set()
    for record in records:
        check(isinstance(record, dict) and set(record) == RECORD_FIELDS,
              "unknown partner response fields, possibly secrets or grants")
        slot = record["slot_id"]
        check(slot in EXPECTED_SLOT_IDS and slot not in seen,
              "unknown or duplicate slot")
        seen.add(slot)
        bounded(record["name"], "candidate name", 120)
        bounded(record["operation"], "candidate operation", 160)
        bounded(record["endpoint_description"], "nonsecret endpoint description", 512)
        bounded(record["source_author"], "source attribution", 160)
        check(isinstance(record["schema_sha256"], str) and
              HEX.fullmatch(record["schema_sha256"]) is not None,
              "missing or malformed proposed schema digest")
        source_url(record["evidence_url"])
    return {
        "schema": RESPONSE_SCHEMA,
        "state": "SELF_REPORTED_CANDIDATES_ONLY",
        "candidate_records": len(records),
        "still_unmapped": [s for s in EXPECTED_SLOT_IDS if s not in seen],
        "independently_verified": 0, "authorized": 0,
        "live_xi_connected": False, "authority": "none",
        "next_step": "Independent out-of-band key verification and exact source/schema pinning; human scope approval separate from this response."
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--registry", type=Path, default=Path(__file__).resolve().parents[2] /
                   "roadmap" / "capability-registry.json")
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("inspect")
    sub.add_parser("request")
    rsp = sub.add_parser("inspect-response")
    rsp.add_argument("--response", type=Path, required=True)
    sub.add_parser("require-live")
    args = p.parse_args(argv)
    try:
        reg = validate_registry(read_json(args.registry))
        if args.action == "request":
            result = make_request(reg)
        elif args.action == "inspect-response":
            result = validate_response(read_json(args.response), reg)
        else:
            result = {
                "schema": REGISTRY_SCHEMA, "state": reg["status"],
                "anonymous_preview_slots": len(reg["xi_slots"]),
                "mapped_xi_capabilities": 0,
                "local_read_only_candidates": len(reg["phi_candidates"]),
                "remote_permissions": 0, "live_xi_connected": False,
                "authority": "none", "registry_sha256": document_hash(reg)
            }
        print(json.dumps(result, sort_keys=True, indent=2))
        if args.action == "require-live":
            print("REFUSED: registry/partner statements never grant live access", file=sys.stderr)
            return 2
        return 0
    except (Refused, OSError, ValueError, UnicodeError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc),
                          "authority": "none", "live_xi_connected": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
