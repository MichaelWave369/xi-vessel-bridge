#!/usr/bin/env python3
"""R9 offline verifier challenge + externally supplied signing-key pins.

This is a SELF-ISSUED FIXTURE demonstration, NOT authentication of Hunter's
real Xi, a live endpoint, or a replacement for a native Xi/TESSERA handshake.

Verifier MUST provide a separately obtained challenge and pin file. Neither
is accepted from the response object. The fixture responder generates its own
pins as a separate demonstration file only; in a real deployment pins MUST be
authenticated out of band before any challenge is considered meaningful.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from xi_peer_r3 import CrossingError, _unb64, canonical
from xi_peer_r4_http import strict_json
from xi_peer_r8_disclosed import build_kit as build_r8, verify_kit as verify_r8

CHALLENGE_VERSION = "xi.phi.challenge.fixture.r9"
PIN_VERSION = "xi.phi.fixture-pins.r9"
RESPONSE_VERSION = "xi.phi.challenge-response.fixture.r9"
ATTEST_VERSION = "xi.phi.r9.challenge_attestation.fixture.v1"
MAX_CHALLENGE_SECONDS = 300
MAX_SKEW_SECONDS = 30
MAX_FILE_BYTES = 128_000
CHALLENGE_FIELDS = {
    "format", "challenge_id", "audience", "nonce_b64", "issued_at", "expires_at",
}
PIN_FIELDS = {"format", "source", "peers"}
RESPONSE_FIELDS = {"format", "challenge_sha256", "r8_witness", "attestations"}
ATTEST_FIELDS = {"statement", "signature_b64"}
STATEMENT_FIELDS = {"format", "signer", "challenge_sha256", "r7_witness_sha256"}
EXPECTED_PEERS = {"phi-fixture", "xi-fixture"}


def sha256(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_challenge(challenge: object, *, now: int | None = None) -> dict:
    if not isinstance(challenge, dict) or set(challenge) != CHALLENGE_FIELDS:
        raise CrossingError("challenge_invalid_shape")
    if challenge["format"] != CHALLENGE_VERSION or challenge["audience"] != "two-synthetic-peers":
        raise CrossingError("challenge_invalid_scope")
    try:
        if str(UUID(challenge["challenge_id"])) != challenge["challenge_id"]:
            raise ValueError()
        nonce = _unb64(challenge["nonce_b64"], 32)
        if not any(nonce):
            raise ValueError()
        at, expiry = challenge["issued_at"], challenge["expires_at"]
        if (type(at) is not int or type(expiry) is not int or at <= 0
                or not 1 <= expiry - at <= MAX_CHALLENGE_SECONDS):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise CrossingError("challenge_invalid") from exc
    tick = int(time.time()) if now is None else now
    if at > tick + MAX_SKEW_SECONDS or tick >= expiry:
        raise CrossingError("challenge_expired_or_future")
    return challenge


def create_challenge(*, now: int | None = None) -> dict:
    at = int(time.time()) if now is None else now
    challenge = {
        "format": CHALLENGE_VERSION,
        "challenge_id": str(uuid4()),
        "audience": "two-synthetic-peers",
        "nonce_b64": base64.b64encode(os.urandom(32)).decode("ascii"),
        "issued_at": at,
        "expires_at": at + 180,
    }
    return validate_challenge(challenge, now=at)


def validate_pins(pins: object) -> dict:
    if (not isinstance(pins, dict) or set(pins) != PIN_FIELDS
            or pins["format"] != PIN_VERSION
            or pins["source"] != "self-issued-disposable-test-identities"
            or not isinstance(pins["peers"], dict)
            or set(pins["peers"]) != EXPECTED_PEERS):
        raise CrossingError("pins_invalid")
    for value in pins["peers"].values():
        _unb64(value, 32)
    if hmac.compare_digest(_unb64(pins["peers"]["phi-fixture"], 32),
                           _unb64(pins["peers"]["xi-fixture"], 32)):
        raise CrossingError("pins_same_key_denied")
    return pins


def create_response(challenge: dict, *, now: int | None = None) -> tuple[dict, dict]:
    validate_challenge(challenge, now=now)
    r8, attestations = build_r8(challenge_commitment=sha256(challenge))
    r7 = r8["r7_witness"]
    pins = {
        "format": PIN_VERSION,
        "source": "self-issued-disposable-test-identities",
        "peers": {
            name: r7["peers"][name]["sign_public_b64"]
            for name in sorted(EXPECTED_PEERS)
        },
    }
    response = {
        "format": RESPONSE_VERSION,
        "challenge_sha256": sha256(challenge),
        "r8_witness": r8,
        "attestations": attestations,
    }
    # No real peer secrets or trust implied. The responder does not return
    # pins inside its response; caller writes them to a separate fixture file.
    verify_response(response, challenge, pins, now=now)
    return response, pins


def verify_response(response: object, challenge: object, pins: object,
                    *, now: int | None = None) -> dict:
    validate_challenge(challenge, now=now)
    validate_pins(pins)
    if not isinstance(response, dict) or set(response) != RESPONSE_FIELDS:
        raise CrossingError("response_invalid_shape")
    if response["format"] != RESPONSE_VERSION:
        raise CrossingError("response_invalid_format")
    commitment = sha256(challenge)
    if response["challenge_sha256"] != commitment:
        raise CrossingError("response_wrong_challenge")
    r8 = response["r8_witness"]
    report = verify_r8(r8)
    if report["status"] != "R8_PUBLIC_PLAINTEXT_BINDING_VERIFIED":
        raise CrossingError("r8_witness_invalid")
    r7 = r8["r7_witness"]
    # Public keys inside the bundle cannot claim trust: pinning comes from
    # explicit, separate caller-supplied file. Do not silently trust TOFU.
    for name in sorted(EXPECTED_PEERS):
        expected = _unb64(pins["peers"][name], 32)
        embedded = _unb64(r7["peers"][name]["sign_public_b64"], 32)
        if not hmac.compare_digest(expected, embedded):
            raise CrossingError("external_pin_mismatch")
    attests = response["attestations"]
    if not isinstance(attests, dict) or set(attests) != EXPECTED_PEERS:
        raise CrossingError("attestations_invalid")
    expected_digest = sha256(r7)
    for name in sorted(EXPECTED_PEERS):
        att = attests[name]
        if not isinstance(att, dict) or set(att) != ATTEST_FIELDS:
            raise CrossingError("attestation_invalid")
        statement = att["statement"]
        if not isinstance(statement, dict) or set(statement) != STATEMENT_FIELDS:
            raise CrossingError("attestation_invalid")
        if (statement["format"] != ATTEST_VERSION or statement["signer"] != name
                or statement["challenge_sha256"] != commitment
                or statement["r7_witness_sha256"] != expected_digest):
            raise CrossingError("attestation_unbound")
        key = Ed25519PublicKey.from_public_bytes(_unb64(pins["peers"][name], 32))
        try:
            key.verify(_unb64(att["signature_b64"], 64), canonical(statement))
        except InvalidSignature as exc:
            raise CrossingError("attestation_signature_invalid") from exc
    return {
        "status": "R9_EXTERNAL_PIN_CHALLENGE_VERIFIED",
        "signers_against_external_pins": 2,
        "challenge_bound_signatures": 2,
        "disclosed_fixture_frames_decrypted": 2,
        "synthetic_keys_self_issued": True,
        "live_xi_connected": False,
        "native_xi_verified": False,
    }


def read_json(path: str) -> dict:
    try:
        with open(path, "rb") as source:
            raw = source.read(MAX_FILE_BYTES + 1)
        if not 0 < len(raw) <= MAX_FILE_BYTES:
            raise CrossingError("fixture_file_size_invalid")
        data = strict_json(raw)
        if not isinstance(data, dict):
            raise CrossingError("fixture_json_invalid")
        return data
    except (ValueError, UnicodeError, TypeError) as exc:
        if isinstance(exc, CrossingError):
            raise
        raise CrossingError("fixture_json_invalid") from exc
    except OSError as exc:
        raise CrossingError("fixture_file_unavailable") from exc


def write_new(path: str, value: dict) -> None:
    target = Path(path)
    if target.is_symlink() or target.exists():
        raise CrossingError("refuse_overwrite_or_symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(target), os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value) + b"\n")


class ChallengeLedger:
    """One-time local verification ledger, NOT a distributed consensus claim."""
    def __init__(self, path: str):
        if not path or path == ":memory:":
            raise ValueError("provide a durable, local challenge-ledger path")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, isolation_level=None, timeout=10)
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS verified (challenge_id TEXT PRIMARY KEY, "
            "response_sha256 TEXT NOT NULL, verified_at INTEGER NOT NULL)"
        )

    def record_once(self, challenge: dict, response: dict, *, now: int | None = None):
        validate_challenge(challenge, now=now)
        at = int(time.time()) if now is None else now
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute(
                "SELECT response_sha256 FROM verified WHERE challenge_id=?",
                (challenge["challenge_id"],),
            ).fetchone()
            if prior is not None:
                raise CrossingError("challenge_replayed" if prior[0] == sha256(response)
                                    else "challenge_conflict")
            self.db.execute(
                "INSERT INTO verified VALUES (?, ?, ?)",
                (challenge["challenge_id"], sha256(response), at),
            )
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def close(self):
        self.db.close()


def main():
    p = argparse.ArgumentParser(description="R9 TEST-ONLY external pin + nonce challenge witness")
    sub = p.add_subparsers(dest="mode", required=True)
    issue = sub.add_parser("challenge", help="issue fresh verifier-owned nonce")
    issue.add_argument("--out", required=True)
    respond = sub.add_parser("respond", help="create self-issued synthetic peer response")
    respond.add_argument("--challenge", required=True)
    respond.add_argument("--out", required=True)
    respond.add_argument("--pins-out", required=True,
                         help="SEPARATE demo pins; independently authenticate real pins out of band")
    verify = sub.add_parser("verify", help="require pins and nonce supplied separately")
    verify.add_argument("--challenge", required=True)
    verify.add_argument("--response", required=True)
    verify.add_argument("--pins", required=True)
    verify.add_argument("--ledger", required=True)
    args = p.parse_args()
    try:
        if args.mode == "challenge":
            write_new(args.out, create_challenge())
            result = {"status": "R9_SYNTHETIC_CHALLENGE_ISSUED", "live_xi_connected": False}
        elif args.mode == "respond":
            if Path(args.out).resolve() == Path(args.pins_out).resolve():
                raise CrossingError("pins_must_be_separate_from_response")
            if (Path(args.out).exists() or Path(args.out).is_symlink()
                    or Path(args.pins_out).exists() or Path(args.pins_out).is_symlink()):
                raise CrossingError("refuse_overwrite_or_symlink")
            challenge = read_json(args.challenge)
            response, pins = create_response(challenge)
            write_new(args.out, response)
            write_new(args.pins_out, pins)
            result = {"status": "R9_SYNTHETIC_RESPONSE_ISSUED", "live_xi_connected": False}
        else:
            challenge = read_json(args.challenge)
            response = read_json(args.response)
            pins = read_json(args.pins)
            result = verify_response(response, challenge, pins)
            ledger = ChallengeLedger(args.ledger)
            try:
                ledger.record_once(challenge, response)
            finally:
                ledger.close()
        print(json.dumps(result, sort_keys=True, indent=2))
    except (CrossingError, ValueError, sqlite3.DatabaseError, OSError) as exc:
        p.error(str(exc) if isinstance(exc, CrossingError) else "fixture_validation_or_storage_error")


if __name__ == "__main__":
    main()
