#!/usr/bin/env python3
"""R11: two independent reviewers attest to one R10 contract digest, offline.

THIS IS A REVIEW RECEIPT, NOT CREDENTIAL AUTHORIZATION OR A LIVE XI CONNECTION.
A signature proves control of a specifically pinned test/operator key, not
whether the named human actually inspected the contract. Operator-owned pins
and grant authority MUST be authenticated independently outside this tool.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from pathlib import Path
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from xi_partner_r10 import validate as validate_r10, synthetic_complete_fixture, strict_load as load_r10
from xi_peer_r3 import _unb64, canonical
from xi_peer_r4_http import strict_json

REQUEST_FORMAT = "xi.phi.dual-review.request.r11"
ATTEST_FORMAT = "xi.phi.dual-review.attestation.r11"
PIN_FORMAT = "xi.phi.dual-review.pins.r11"
ROLES = {"xi_reviewer", "phi_reviewer"}
MAX_FILE = 48_000
MAX_AGE = 900
REQUEST_FIELDS = {"format", "request_id", "contract_sha256", "classification",
                  "room_id", "scopes", "issued_at", "expires_at", "intent"}
STATEMENT_FIELDS = {"format", "role", "request_sha256", "decision", "signed_at"}
ATTEST_FIELDS = {"statement", "signature_b64"}
PIN_FIELDS = {"format", "origin", "reviewer_signing_public_keys"}
INTENT = "review_exact_contract_only_no_execution_or_posting"
DECISION = "reviewed_candidate_not_execution_permission"


class ReviewError(ValueError):
    """Validation errors exclude input content and secret bytes."""


def sha256(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_doc(path: str) -> dict:
    try:
        with open(path, "rb") as source:
            raw = source.read(MAX_FILE + 1)
        if not raw or len(raw) > MAX_FILE:
            raise ReviewError("review_input_size_invalid")
        result = strict_json(raw)
        if not isinstance(result, dict):
            raise ReviewError("review_input_invalid")
        return result
    except (ValueError, TypeError, UnicodeError) as exc:
        if isinstance(exc, ReviewError):
            raise
        raise ReviewError("review_json_invalid") from exc
    except OSError as exc:
        raise ReviewError("review_file_unavailable") from exc


def write_new(path: str, obj: dict) -> None:
    target = Path(path)
    if target.exists() or target.is_symlink():
        raise ReviewError("refuse_overwrite_or_symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(obj) + b"\n")


def read_private_signer(path: str) -> Ed25519PrivateKey:
    """Read operator-held raw Ed25519 seed, NOT Xi API key or tessera."""
    if Path(path).is_symlink():
        raise ReviewError("signing_key_unavailable")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != 32:
                raise ReviewError("invalid_signing_key_file")
            if os.name == "posix" and (info.st_mode & 0o077):
                raise ReviewError("insecure_signing_key_permissions")
            key_bytes = os.read(fd, 33)
        finally:
            os.close(fd)
        return Ed25519PrivateKey.from_private_bytes(key_bytes)
    except OSError as exc:
        raise ReviewError("signing_key_unavailable") from exc
    except ValueError as exc:
        if isinstance(exc, ReviewError):
            raise
        raise ReviewError("invalid_signing_key_file") from exc


def make_request(contract: dict, *, now: int | None = None) -> dict:
    status = validate_r10(contract)
    if status["missing_requirements"]:
        raise ReviewError("contract_incomplete")
    if status["status"] not in ("R10_SYNTHETIC_SHAPE_VERIFIED",
                                "R10_STAGING_CANDIDATE_REQUIRES_JOINT_REVIEW"):
        raise ReviewError("contract_not_reviewable")
    at = int(time.time()) if now is None else now
    return {
        "format": REQUEST_FORMAT, "request_id": str(uuid4()),
        "contract_sha256": status["contract_sha256"],
        "classification": contract["classification"],
        "room_id": contract["room"]["room_id"],
        "scopes": sorted(contract["authorization"]["scopes"]),
        "issued_at": at, "expires_at": at + 600, "intent": INTENT,
    }


def check_request(request: dict, contract: dict, *, now: int | None = None) -> None:
    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS or request.get("format") != REQUEST_FORMAT:
        raise ReviewError("review_request_invalid")
    try:
        if str(UUID(request["request_id"])) != request["request_id"]:
            raise ValueError()
        at, end = request["issued_at"], request["expires_at"]
        if type(at) is not int or type(end) is not int or at <= 0 or not 1 <= end-at <= MAX_AGE:
            raise ValueError()
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise ReviewError("review_request_invalid") from exc
    current = int(time.time()) if now is None else now
    if current < at-30 or current >= end:
        raise ReviewError("review_request_expired_or_future")
    expected = validate_r10(contract)
    if expected["missing_requirements"]:
        raise ReviewError("contract_incomplete")
    if (request["intent"] != INTENT
            or request["contract_sha256"] != expected["contract_sha256"]
            or request["classification"] != contract["classification"]
            or request["room_id"] != contract["room"]["room_id"]
            or request["scopes"] != sorted(contract["authorization"]["scopes"])):
        raise ReviewError("review_contract_binding_mismatch")


def make_attestation(request: dict, contract: dict, role: str,
                     signer: Ed25519PrivateKey, *, now: int | None = None) -> dict:
    check_request(request, contract, now=now)
    if role not in ROLES:
        raise ReviewError("review_role_invalid")
    at = int(time.time()) if now is None else now
    statement = {
        "format": ATTEST_FORMAT, "role": role,
        "request_sha256": sha256(request), "decision": DECISION,
        "signed_at": at,
    }
    return {"statement": statement,
            "signature_b64": base64.b64encode(signer.sign(canonical(statement))).decode("ascii")}


def _validate_pins(pins: dict) -> dict:
    if (not isinstance(pins, dict) or set(pins) != PIN_FIELDS
            or pins["format"] != PIN_FORMAT
            or pins["origin"] not in ("synthetic_self_issued", "operator_supplied_unverified")
            or not isinstance(pins["reviewer_signing_public_keys"], dict)
            or set(pins["reviewer_signing_public_keys"]) != ROLES):
        raise ReviewError("review_pins_invalid")
    values = [_unb64(pins["reviewer_signing_public_keys"][role], 32) for role in sorted(ROLES)]
    if values[0] == values[1]:
        raise ReviewError("reviewers_must_use_distinct_keys")
    return pins


def verify(contract: dict, request: dict, attests: dict,
           pins: dict, *, now: int | None = None) -> dict:
    check_request(request, contract, now=now)
    _validate_pins(pins)
    if not isinstance(attests, dict) or set(attests) != ROLES:
        raise ReviewError("both_reviewers_required")
    for role in sorted(ROLES):
        att = attests[role]
        if not isinstance(att, dict) or set(att) != ATTEST_FIELDS:
            raise ReviewError("attestation_invalid")
        statement = att["statement"]
        if not isinstance(statement, dict) or set(statement) != STATEMENT_FIELDS:
            raise ReviewError("attestation_invalid")
        at = statement["signed_at"]
        if (statement["format"] != ATTEST_FORMAT
                or statement["role"] != role
                or statement["decision"] != DECISION
                or statement["request_sha256"] != sha256(request)
                or type(at) is not int
                or at < request["issued_at"]-30
                or at > request["expires_at"]):
            raise ReviewError("attestation_unbound")
        key = Ed25519PublicKey.from_public_bytes(
            _unb64(pins["reviewer_signing_public_keys"][role], 32))
        try:
            key.verify(_unb64(att["signature_b64"], 64), canonical(statement))
        except InvalidSignature as exc:
            raise ReviewError("review_signature_invalid") from exc
    return {
        "status": "R11_DUAL_REVIEW_SIGNATURES_VERIFIED_NOT_AUTHORIZED",
        "request_id": request["request_id"],
        "contract_sha256": request["contract_sha256"],
        "review_signatures_verified": 2,
        "pins_source_claim": pins["origin"],
        "keys_independently_authenticated": False,
        "human_approval_verified": False,
        "grant_issued": False, "transport_invoked": False,
        "live_xi_connected": False,
    }


class ReviewReplayLedger:
    def __init__(self, path: str):
        if not path or path == ":memory:":
            raise ReviewError("durable_ledger_required")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS reviews (request_id TEXT PRIMARY KEY, "
            "contract_sha256 TEXT NOT NULL, verified_at INTEGER NOT NULL)"
        )

    def reserve(self, request: dict, *, now: int | None = None):
        at = int(time.time()) if now is None else now
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self.db.execute("SELECT contract_sha256 FROM reviews WHERE request_id=?",
                                  (request["request_id"],)).fetchone()
            if old:
                raise ReviewError("review_replayed" if old[0] == request["contract_sha256"]
                                  else "review_id_conflict")
            self.db.execute("INSERT INTO reviews VALUES (?,?,?)",
                            (request["request_id"], request["contract_sha256"], at))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def close(self):
        self.db.close()


def fixture_bundle() -> tuple[dict, dict, dict, dict]:
    """All keys temporary and in RAM. This is NEVER a real approval record."""
    contract = synthetic_complete_fixture()
    request = make_request(contract)
    keys = {role: Ed25519PrivateKey.generate() for role in ROLES}
    attests = {role: make_attestation(request, contract, role, keys[role])
               for role in ROLES}
    pins = {"format": PIN_FORMAT, "origin": "synthetic_self_issued",
            "reviewer_signing_public_keys": {}}
    for role in sorted(ROLES):
        pub = keys[role].public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        pins["reviewer_signing_public_keys"][role] = base64.b64encode(pub).decode("ascii")
    verify(contract, request, attests, pins)
    return contract, request, attests, pins


def main():
    p = argparse.ArgumentParser(description="R11 OFFLINE reviewer signature receipt, NOT operational permission")
    sub = p.add_subparsers(dest="cmd", required=True)
    demo = sub.add_parser("fixture", help="generate public synthetic DEMO records only")
    demo.add_argument("--dir", required=True)
    issue = sub.add_parser("issue", help="create exact-hash, review-only request from R10 candidate")
    issue.add_argument("--contract", required=True)
    issue.add_argument("--out", required=True)
    sign = sub.add_parser("sign", help="sign review-only receipt with local operator-held Ed25519 seed")
    for flag in ("contract", "request", "role", "private-key", "out"):
        sign.add_argument("--" + flag, required=True)
    check = sub.add_parser("verify", help="verify both signatures using separately supplied pins")
    for flag in ("contract", "request", "xi-attestation", "phi-attestation", "pins", "ledger"):
        check.add_argument("--" + flag, required=True)
    args = p.parse_args()
    try:
        if args.cmd == "fixture":
            directory = Path(args.dir)
            # Refuse to accidentally overwrite a previous witness.
            if directory.exists() and any(directory.iterdir()):
                raise ReviewError("fixture_directory_not_empty")
            a, b, c, d = fixture_bundle()
            for name, value in (("contract.json", a), ("request.json", b),
                                ("xi-attestation.json", c["xi_reviewer"]),
                                ("phi-attestation.json", c["phi_reviewer"]),
                                ("self-issued-demo-pins.json", d)):
                write_new(str(directory / name), value)
            result = verify(a, b, c, d)
        elif args.cmd == "issue":
            contract = load_r10(args.contract)
            request = make_request(contract)
            write_new(args.out, request)
            result = {"status": "R11_REVIEW_REQUEST_ISSUED_ONLY",
                      "contract_sha256": request["contract_sha256"],
                      "no_authorization_granted": True, "live_xi_connected": False}
        elif args.cmd == "sign":
            contract = load_r10(args.contract)
            request = read_doc(args.request)
            key = read_private_signer(args.private_key)
            receipt = make_attestation(request, contract, args.role, key)
            write_new(args.out, receipt)
            result = {"status": "R11_REVIEW_ATTESTATION_SIGNED_ONLY",
                      "role": args.role, "no_authorization_granted": True,
                      "live_xi_connected": False}
        else:
            contract = load_r10(args.contract)
            request = read_doc(args.request)
            attests = {"xi_reviewer": read_doc(args.xi_attestation),
                       "phi_reviewer": read_doc(args.phi_attestation)}
            pins = read_doc(args.pins)
            result = verify(contract, request, attests, pins)
            ledger = ReviewReplayLedger(args.ledger)
            try:
                ledger.reserve(request)
            finally:
                ledger.close()
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (ReviewError, ValueError, OSError, sqlite3.DatabaseError) as exc:
        p.error(str(exc) if isinstance(exc, ReviewError) else "review_invalid_or_storage_unavailable")


if __name__ == "__main__":
    sys.exit(main())
