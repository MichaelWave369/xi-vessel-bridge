#!/usr/bin/env python3
"""R17 candidate-only Xi ⇄ PHI369 roadmap inspector (no external access).

A machine-readable planning artifact cannot certify a live link or human consent.
Fail closed on false promotion of external milestones or extra authority fields.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.parse import urlparse

SCHEMA = "PhiXi.SharedRoadmap.v1"
IDS = ("R15", "R16", "R17", "R18", "R19", "R20")
GATE_IDS = (
    "identity", "native_contract", "two_operator_approval", "transport_profile",
    "least_privilege", "consent", "provenance", "kill_switch",
    "two_host_transcript", "durable_receipts", "negative_controls",
    "human_data_scope", "capsule_byte_integrity", "revocation_drill",
    "both_houses_independent", "disaster_recovery_drill",
)
ROOT_FIELDS = {"schema", "title", "snapshot_date", "status", "live_xi_connected",
               "authority", "principles", "xi_public_preview", "milestones",
               "gates", "capability_candidates"}
MILESTONE_FIELDS = {"id", "title", "state", "depends_on", "gate_ids", "evidence_links", "note"}
GATE_FIELDS = {"id", "owner", "state", "requirement"}
CANDIDATE_FIELDS = {"label", "origin", "state", "source"}


class RoadmapRefused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise RoadmapRefused(reason)


def text(value, name, max_chars=512):
    require(isinstance(value, str) and 0 < len(value) <= max_chars, "invalid " + name)
    return value


def public_url(value):
    text(value, "source URL", 1024)
    parsed = urlparse(value)
    require(parsed.scheme == "https" and parsed.hostname in {
        "www.xi-field.com", "github.com"
    } and not parsed.username and not parsed.password, "unapproved source URL")
    return value


def unique(items, name):
    require(isinstance(items, list) and len(items) == len(set(items)), "invalid or duplicate " + name)
    return items


def validate(doc):
    require(isinstance(doc, dict) and set(doc) == ROOT_FIELDS, "roadmap root field mismatch")
    require(doc["schema"] == SCHEMA, "unsupported roadmap schema")
    text(doc["title"], "title")
    require(doc["snapshot_date"] == "2026-10-25", "snapshot date must be explicitly reviewed when updated")
    require(doc["status"] == "candidate_planning_only", "false candidate readiness claim")
    require(doc["live_xi_connected"] is False and doc["authority"] == "none",
            "a roadmap cannot confer live connection or authority")
    require(isinstance(doc["principles"], list) and len(doc["principles"]) >= 3, "missing principles")
    for principle in doc["principles"]:
        text(principle, "principle")
    preview = doc["xi_public_preview"]
    require(isinstance(preview, dict) and set(preview) == {
        "source", "capabilities_count", "sovereign_doors_count",
        "verified_capability_ids", "verified_door_ids", "disclosure"
    }, "bad preview fields")
    public_url(preview["source"])
    require(preview["capabilities_count"] == 13 and type(preview["capabilities_count"]) is int,
            "public preview count changed: re-review upstream")
    require(preview["sovereign_doors_count"] == 12 and type(preview["sovereign_doors_count"]) is int,
            "public door preview count changed: re-review upstream")
    require(preview["verified_capability_ids"] == [] and preview["verified_door_ids"] == [],
            "public previews are not verified capability or door identities")
    text(preview["disclosure"], "disclosure", 2048)

    gates = doc["gates"]
    require(isinstance(gates, list) and len(gates) == len(GATE_IDS), "gate count mismatch")
    gate_ids = []
    for gate in gates:
        require(isinstance(gate, dict) and set(gate) == GATE_FIELDS, "gate schema mismatch")
        gate_ids.append(text(gate["id"], "gate ID", 64))
        text(gate["owner"], "gate owner", 80)
        text(gate["requirement"], "gate requirement", 1024)
        # A reviewer cannot bootstrap independent partner evidence by editing a JSON field.
        require(gate["state"] in ("missing", "candidate_unverified"), "unverified gate promoted")
    require(set(unique(gate_ids, "gate IDs")) == set(GATE_IDS), "missing or invented gate IDs")

    milestones = doc["milestones"]
    require(isinstance(milestones, list) and len(milestones) == len(IDS), "milestone count mismatch")
    seen = []
    for milestone in milestones:
        require(isinstance(milestone, dict) and set(milestone) == MILESTONE_FIELDS,
                "milestone schema mismatch")
        mid = text(milestone["id"], "milestone ID", 8)
        seen.append(mid)
        text(milestone["title"], "milestone title", 128)
        text(milestone["note"], "milestone note", 1024)
        unique(milestone["depends_on"], "dependencies")
        unique(milestone["gate_ids"], "milestone gates")
        require(set(milestone["gate_ids"]).issubset(GATE_IDS), "unknown referenced gate")
        require(isinstance(milestone["evidence_links"], list), "evidence links must be a list")
        for source in milestone["evidence_links"]:
            public_url(source)
        if mid in ("R15", "R16"):
            require(milestone["state"] == "local_fixture_verified", "known fixture status altered")
            require(len(milestone["evidence_links"]) > 0, "fixture has no source")
            require(milestone["gate_ids"] == [], "local fixture cannot satisfy external gates")
        elif mid == "R17":
            require(milestone["state"] == "blocked" and milestone["evidence_links"] == [],
                    "candidate R17 is not an independently completed field pilot")
        else:
            require(milestone["state"] == "planned" and milestone["evidence_links"] == [],
                    "later field milestone falsely promoted")
    require(unique(seen, "milestone IDs") == list(IDS), "roadmap phase order mismatch")
    for i, milestone in enumerate(milestones):
        expected = [] if i == 0 else [IDS[i - 1]]
        require(milestone["depends_on"] == expected, "unexpected milestone dependency")
    require(set(milestones[2]["gate_ids"]) == set(GATE_IDS[:8]),
            "missing a foundational R17 gate")

    candidates = doc["capability_candidates"]
    require(isinstance(candidates, list) and 1 <= len(candidates) <= 20,
            "invalid candidate list")
    names = []
    for item in candidates:
        require(isinstance(item, dict) and set(item) == CANDIDATE_FIELDS,
                "capability candidate schema mismatch")
        names.append(text(item["label"], "capability label", 120))
        text(item["origin"], "capability origin")
        require(item["state"] in ("fixture_only", "candidate_unconfirmed"),
                "candidate capability falsely promoted")
        public_url(item["source"])
    unique(names, "capability labels")
    return doc


def report(doc):
    validate(doc)
    missing = [gate["id"] for gate in doc["gates"] if gate["state"] == "missing"]
    return {
        "schema": SCHEMA,
        "roadmap_status": "candidate_planning_only",
        "snapshot_date": doc["snapshot_date"],
        "local_fixture_milestones": ["R15", "R16"],
        "external_pilot_status": "BLOCKED",
        "r17_missing_gates": missing,
        "r17_unverified_candidate_gates": [
            gate["id"] for gate in doc["gates"] if gate["state"] == "candidate_unverified"
        ],
        "advertised_preview_counts": {
            "capabilities": doc["xi_public_preview"]["capabilities_count"],
            "doors": doc["xi_public_preview"]["sovereign_doors_count"]
        },
        "trusted_remote_capability_count": 0,
        "live_xi_connected": False,
        "authority": "none",
        "verification": "schema-and-claim-boundaries-only-not-partner-evidence",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=Path(__file__).resolve().parents[2] /
                        "roadmap" / "bridge-roadmap.json")
    parser.add_argument("--require-live", action="store_true",
                        help="Always fail closed: external proof cannot be certified from candidate JSON")
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.file.read_text(encoding="utf-8"))
        summary = report(data)
        print(json.dumps(summary, indent=2, sort_keys=True))
        if args.require_live:
            print("R17_REFUSED: static roadmap is not cross-peer authorization", file=sys.stderr)
            return 2
        return 0
    except (RoadmapRefused, OSError, ValueError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc),
                          "live_xi_connected": False, "authority": "none"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
