#!/usr/bin/env python3
"""R12: portable, OFFLINE, transport-neutral partner conformance questionnaire.

Does NOT define or implement Xi-native .xi/TESSERA encoding, call any service,
execute submitted operations, authenticate a partner, or issue permissions.
The suite is deterministic and synthetic; responses are UNTRUSTED self-reports.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

SUITE_FORMAT = "xi.phi.partner.exercises.synthetic.r12"
RESPONSE_FORMAT = "xi.phi.partner.observations.self-reported.r12"
MAX_FILE_BYTES = 80_000
SUITE_FIELDS = {"format", "classification", "notice", "cases"}
CASE_FIELDS = {"case_id", "scenario", "request_id", "payload_b64",
               "payload_sha256", "declared_payload_sha256", "provenance_sha256",
               "expected_decision", "expected_processing_count"}
RESPONSE_FIELDS = {"format", "suite_sha256", "origin", "peer_label", "observations"}
OBS_FIELDS = {"case_id", "status", "decision", "observed_payload_sha256",
              "observed_provenance_sha256", "processing_count", "denial_code"}
SCENARIOS = [
    ("four_name_opaque_bytes", "accepted", 1),
    ("unicode_exact_bytes", "accepted", 1),
    ("provenance_preserved", "accepted", 1),
    ("declared_digest_tampered", "denied", 0),
    ("wrong_room_denied", "denied", 0),
    ("revoked_grant_denied", "denied", 0),
    ("unknown_tool_never_executed", "denied", 0),
    ("duplicate_delivery_idempotent", "accepted", 1),
]
DENIAL_CODES = {
    "declared_digest_tampered": "hash_mismatch",
    "wrong_room_denied": "scope_denied",
    "revoked_grant_denied": "grant_revoked",
    "unknown_tool_never_executed": "unknown_operation",
}
PUBLIC_NOTICE = (
    "SYNTHETIC SELF-REPORTED EXERCISES ONLY. Not Xi/TESSERA-native, not an API "
    "contract, not authenticated runtime evidence, not real posting permission. "
    "No credentials or private conversations. Do not execute tool payloads."
)
PEER_RE = re.compile(r"[a-z][a-z0-9-]{1,47}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")


class ExerciseError(ValueError):
    """Diagnostic reason codes never echo partner-provided strings."""


def canonical(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(obj: object) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def _bytes_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ExerciseError("duplicate_json_key")
        obj[key] = value
    return obj


def read_json(path: str) -> dict:
    try:
        with open(path, "rb") as file:
            raw = file.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ExerciseError("input_file_unavailable") from exc
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise ExerciseError("input_size_invalid")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError()))
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except (ValueError, UnicodeError, TypeError) as exc:
        if isinstance(exc, ExerciseError):
            raise
        raise ExerciseError("invalid_json") from exc


def write_new(path: str, obj: dict):
    p = Path(path)
    if p.exists() or p.is_symlink():
        raise ExerciseError("refuse_overwrite_or_symlink")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    with os.fdopen(fd, "wb") as output:
        output.write(canonical(obj) + b"\n")


def _payload(scenario: str) -> bytes:
    if scenario == "four_name_opaque_bytes":
        return b"xi-vessel-bridge\nCommonline\nFieldAccord\nthink-tank"
    if scenario == "unicode_exact_bytes":
        return "⟨ Ξ ⋈ Φ ⟩\nÉcole 🌌".encode("utf-8")
    if scenario == "provenance_preserved":
        return canonical({"text": "synthetic capsule", "attrs": {"nested": [1, 2, 3]}})
    if scenario == "declared_digest_tampered":
        return b"unchanged-synthetic-bytes"
    if scenario == "wrong_room_denied":
        return b"wrong-room-synthetic-only"
    if scenario == "revoked_grant_denied":
        return b"revoked-synthetic-only"
    if scenario == "unknown_tool_never_executed":
        return b"opaque-UNSUPPORTED-OPERATION-never-execute"
    if scenario == "duplicate_delivery_idempotent":
        return b"duplicate-synthetic-only"
    raise ExerciseError("unknown_scenario")


def make_suite() -> dict:
    provenance = {
        "author": "offline-fixture", "source": "r12-conformance",
        "version": "1", "intended_use": "non-executing-interop-evidence",
    }
    cases = []
    for scenario, decision, count in SCENARIOS:
        raw = _payload(scenario)
        source_digest = _bytes_digest(raw)
        case = {
            "case_id": scenario,
            "scenario": scenario,
            "request_id": str(uuid5(NAMESPACE_URL, "xi.phi.r12:" + scenario)),
            "payload_b64": base64.b64encode(raw).decode("ascii"),
            "payload_sha256": source_digest,
            "declared_payload_sha256": "0" * 64 if scenario == "declared_digest_tampered" else source_digest,
            "provenance_sha256": digest(provenance),
            "expected_decision": decision,
            "expected_processing_count": count,
        }
        cases.append(case)
    return {
        "format": SUITE_FORMAT,
        "classification": "offline_synthetic_exercises_only",
        "notice": PUBLIC_NOTICE,
        "cases": cases,
    }


def validate_suite(suite: object) -> dict:
    """Case corpus is immutable; no respondent may relax checks by editing it."""
    if not isinstance(suite, dict) or set(suite) != SUITE_FIELDS:
        raise ExerciseError("suite_shape_invalid")
    try:
        if canonical(suite) != canonical(make_suite()):
            raise ExerciseError("suite_fixture_mismatch")
    except (ValueError, TypeError) as exc:
        if isinstance(exc, ExerciseError):
            raise
        raise ExerciseError("suite_fixture_mismatch") from exc
    return suite


def make_response_template(suite: dict, *, synthetic_example: bool = False) -> dict:
    validate_suite(suite)
    items = []
    for case in suite["cases"]:
        if synthetic_example:
            decision = case["expected_decision"]
            accepted = decision == "accepted"
            items.append({
                "case_id": case["case_id"], "status": "measured",
                "decision": decision,
                "observed_payload_sha256": case["payload_sha256"] if accepted else None,
                "observed_provenance_sha256": case["provenance_sha256"] if accepted else None,
                "processing_count": case["expected_processing_count"],
                "denial_code": DENIAL_CODES.get(case["case_id"]) if not accepted else None,
            })
        else:
            items.append({
                "case_id": case["case_id"], "status": "not_run",
                "decision": None, "observed_payload_sha256": None,
                "observed_provenance_sha256": None,
                "processing_count": None, "denial_code": None,
            })
    return {
        "format": RESPONSE_FORMAT, "suite_sha256": digest(suite),
        "origin": "synthetic_local_example" if synthetic_example else "partner_self_report",
        "peer_label": "synthetic-demo" if synthetic_example else "unverified-peer",
        "observations": items,
    }


def _check_hex(value: object) -> bool:
    return isinstance(value, str) and bool(HEX_RE.fullmatch(value))


def assess(suite: object, response: object) -> dict:
    validate_suite(suite)
    if (not isinstance(response, dict) or set(response) != RESPONSE_FIELDS
            or response["format"] != RESPONSE_FORMAT):
        raise ExerciseError("response_shape_invalid")
    if response["suite_sha256"] != digest(suite):
        raise ExerciseError("wrong_suite_digest")
    if response["origin"] not in ("partner_self_report", "synthetic_local_example"):
        raise ExerciseError("response_origin_invalid")
    peer = response["peer_label"]
    if not isinstance(peer, str) or not PEER_RE.fullmatch(peer):
        raise ExerciseError("peer_label_invalid")
    observations = response["observations"]
    if not isinstance(observations, list) or len(observations) != len(SCENARIOS):
        raise ExerciseError("observation_count_invalid")
    cases = {c["case_id"]: c for c in suite["cases"]}
    seen = set()
    passed, failed, unresolved, per_case = [], [], [], []
    for obs in observations:
        if not isinstance(obs, dict) or set(obs) != OBS_FIELDS:
            raise ExerciseError("observation_shape_invalid")
        key = obs["case_id"]
        if not isinstance(key, str) or key not in cases or key in seen:
            raise ExerciseError("duplicate_or_unknown_case")
        seen.add(key)
        status = obs["status"]
        if status not in ("not_run", "unsupported", "measured"):
            raise ExerciseError("observation_status_invalid")
        case = cases[key]
        if status != "measured":
            if (obs["decision"] is not None
                    or obs["observed_payload_sha256"] is not None
                    or obs["observed_provenance_sha256"] is not None
                    or obs["processing_count"] is not None
                    or obs["denial_code"] is not None):
                raise ExerciseError("unmeasured_case_has_claims")
            result = "UNRESOLVED"
            unresolved.append(key)
        else:
            decision = obs["decision"]
            count = obs["processing_count"]
            if (decision not in ("accepted", "denied")
                    or type(count) is not int or count < 0 or count > 2):
                raise ExerciseError("invalid_measured_outcome")
            hashes = (obs["observed_payload_sha256"], obs["observed_provenance_sha256"])
            if any(v is not None and not _check_hex(v) for v in hashes):
                raise ExerciseError("invalid_observed_digest")
            denial = obs["denial_code"]
            if denial is not None and denial not in set(DENIAL_CODES.values()):
                raise ExerciseError("invalid_denial_code")
            correct = (decision == case["expected_decision"]
                       and count == case["expected_processing_count"])
            if correct and decision == "accepted":
                correct = (obs["observed_payload_sha256"] == case["payload_sha256"]
                           and obs["observed_provenance_sha256"] == case["provenance_sha256"]
                           and denial is None)
            elif correct and decision == "denied":
                correct = (all(h is None for h in hashes)
                           and denial == DENIAL_CODES[key])
            if correct:
                passed.append(key)
                result = "SELF_REPORTED_MATCH"
            else:
                failed.append(key)
                result = "SELF_REPORTED_MISMATCH"
        per_case.append({"case_id": key, "result": result})
    if failed:
        verdict = "R12_SELF_REPORTED_MISMATCHES"
    elif unresolved:
        verdict = "R12_PARTNER_EVIDENCE_PENDING"
    else:
        verdict = "R12_SELF_REPORTED_MATCHES_NOT_AUTHENTICATED"
    return {
        "status": verdict,
        "suite_sha256": digest(suite),
        "response_sha256": digest(response),
        "response_origin": response["origin"],
        "case_count": len(cases),
        "self_reported_matches": len(passed),
        "self_reported_mismatches": len(failed),
        "unresolved": len(unresolved),
        "cases": sorted(per_case, key=lambda x: x["case_id"]),
        "partner_identity_authenticated": False,
        "actual_xi_runtime_observed": False,
        "native_xi_tessera_verified": False,
        "grant_or_permission_verified": False,
        "tool_or_model_executed": False,
        "live_xi_connected": False,
    }


def main():
    parser = argparse.ArgumentParser(description="R12 NO NETWORK / NO EXECUTION partner exercise kit")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("generate", help="create suite, unfilled answer and synthetic example")
    create.add_argument("--dir", required=True)
    inspect = commands.add_parser("assess", help="check self-reported offline responses, not live trust")
    inspect.add_argument("--suite", required=True)
    inspect.add_argument("--response", required=True)
    inspect.add_argument("--require-all-matches", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "generate":
            suite = make_suite()
            directory = Path(args.dir)
            files = {
                "suite.json": suite,
                "response-template.json": make_response_template(suite),
                "synthetic-example-response.json": make_response_template(suite, synthetic_example=True),
            }
            if any((directory / name).exists() or (directory / name).is_symlink() for name in files):
                raise ExerciseError("refuse_overwrite")
            for name, data in files.items():
                write_new(str(directory / name), data)
            report = assess(suite, files["response-template.json"])
        else:
            report = assess(read_json(args.suite), read_json(args.response))
        print(json.dumps(report, indent=2, sort_keys=True))
        if args.command == "assess" and args.require_all_matches:
            return 0 if report["status"] == "R12_SELF_REPORTED_MATCHES_NOT_AUTHENTICATED" else 2
        return 0
    except (ExerciseError, OSError, TypeError, ValueError) as exc:
        parser.error(str(exc) if isinstance(exc, ExerciseError) else "invalid_conformance_input")


if __name__ == "__main__":
    sys.exit(main())
