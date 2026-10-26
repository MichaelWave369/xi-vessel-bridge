#!/usr/bin/env python3
"""R18.10 Ed25519 cross-language math fixture; key is ephemeral and UNPINNED.

A valid signature proves only possession of a just-created local test private
key. It does NOT authenticate Xi, a real partner, the signer, authorization,
delivery, replay protection, or any actual exchange. No network or real grants.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

import xi_receipt_r189 as base

SCHEMA = "PhiXi.R18_10_SelfIssuedLocalSignatureFixture.v1"
RESULT_SCHEMA = "PhiXi.R18_10_SelfIssuedVerificationReport.v1"
SUITE = "Ed25519_UNPINNED_EPHEMERAL_TEST_ONLY"
CONTEXT = b"PhiXi.R18_10.SelfIssuedSyntheticReceipt.v1\x00"
FIELDS = {
    "schema", "suite", "case_id", "receipt_b64", "receipt_sha256",
    "domain_message_sha256", "public_key_hex", "signature_hex",
    "signer_classification", "self_issued", "real_xi_identity_verified",
    "bilateral_consent_verified", "approved_operations", "signed_exchange_observed",
    "r17_external_pilot", "r18_real_two_host_pilot", "live_xi_connected",
    "authority"
}
MAX_BYTES = 8192
BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
LOWER_HEX = re.compile(r"^[0-9a-f]+$")


class Refused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unsigned(case_id):
    return base.emit(case_id)


def domain_message(receipt):
    return CONTEXT + receipt


def _strict_b64_decode(value):
    require(type(value) is str and 0 < len(value) < 6000 and
            BASE64.fullmatch(value) is not None, "bad base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refused("bad base64") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical base64")
    return raw


def _hex_bytes(text, expected_length):
    require(type(text) is str and len(text) == expected_length * 2 and
            LOWER_HEX.fullmatch(text) is not None, "bad fixed-size hex field")
    return bytes.fromhex(text)


def create(case_id):
    receipt = unsigned(case_id)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    message = domain_message(receipt)
    signature = private.sign(message)
    # Private key is deliberately not retained, printed, exported, or stored.
    envelope = {
        "schema": SCHEMA,
        "suite": SUITE,
        "case_id": case_id,
        "receipt_b64": base64.b64encode(receipt).decode("ascii"),
        "receipt_sha256": sha(receipt),
        "domain_message_sha256": sha(message),
        "public_key_hex": public.hex(),
        "signature_hex": signature.hex(),
        "signer_classification": "UNPINNED_SELF_ISSUED_LOCAL_KEY",
        "self_issued": True,
        "real_xi_identity_verified": False,
        "bilateral_consent_verified": False,
        "approved_operations": 0,
        "signed_exchange_observed": False,
        "r17_external_pilot": "BLOCKED",
        "r18_real_two_host_pilot": "NOT_RUN",
        "live_xi_connected": False,
        "authority": "none",
    }
    return base.canonical(envelope)


def _unique(pairs):
    obj = {}
    for key, val in pairs:
        require(key not in obj, "duplicate JSON key")
        obj[key] = val
    return obj


def _forbid_number(_):
    raise Refused("unsupported number")


def verify(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_BYTES, "invalid envelope size")
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=_unique,
                           parse_float=_forbid_number, parse_constant=_forbid_number)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused("invalid ASCII JSON") from exc
    require(type(value) is dict and set(value) == FIELDS, "unexpected envelope keys")
    require(base.canonical(value) == data, "envelope JSON not canonical")
    require(value["schema"] == SCHEMA and value["suite"] == SUITE and
            value["signer_classification"] == "UNPINNED_SELF_ISSUED_LOCAL_KEY" and
            value["self_issued"] is True and
            value["real_xi_identity_verified"] is False and
            value["bilateral_consent_verified"] is False and
            type(value["approved_operations"]) is int and value["approved_operations"] == 0 and
            value["signed_exchange_observed"] is False and
            value["r17_external_pilot"] == "BLOCKED" and
            value["r18_real_two_host_pilot"] == "NOT_RUN" and
            value["live_xi_connected"] is False and value["authority"] == "none",
            "self-issued fixture attempted privilege promotion")
    receipt = _strict_b64_decode(value["receipt_b64"])
    base.verify(receipt)
    require(type(value["case_id"]) is str and value["case_id"] in base.CASES and
            value["case_id"] == json.loads(receipt)["case_id"], "case mismatch")
    require(value["receipt_sha256"] == sha(receipt), "receipt digest mismatch")
    message = domain_message(receipt)
    require(value["domain_message_sha256"] == sha(message), "domain binding changed")
    pub = _hex_bytes(value["public_key_hex"], 32)
    sig = _hex_bytes(value["signature_hex"], 64)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
    except (InvalidSignature, ValueError) as exc:
        raise Refused("invalid self-issued mathematical signature") from exc
    return {
        "schema": RESULT_SCHEMA,
        "status": "SELF_ISSUED_EPHEMERAL_SIGNATURE_MATH_VALID",
        "case_id": value["case_id"],
        "receipt_sha256": sha(receipt),
        "domain_message_sha256": sha(message),
        "self_issued_signature_verified": True,
        "independent_partner_identity_verified": False,
        "operator_approvals": 0,
        "approved_operations": 0,
        "external_gates_promoted": 0,
        "real_two_host_crossing_tested": False,
        "live_xi_connected": False,
        "authority": "none",
    }


def read(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_BYTES,
            "file unavailable, symbolic link or too large")
    raw = p.read_bytes()
    require(len(raw) <= MAX_BYTES, "file changed while reading")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    generate = sub.add_parser("emit")
    generate.add_argument("--case", required=True, choices=tuple(base.CASES))
    generate.add_argument("--out", type=Path)
    validation = sub.add_parser("verify")
    validation.add_argument("--file", required=True, type=Path)
    sub.add_parser("require-live")
    args = parser.parse_args(argv)
    if args.action == "require-live":
        print('{"status":"LIVE_AUTHORITY_REFUSED","authority":"none"}')
        return 2
    try:
        if args.action == "emit":
            result = create(args.case)
            if args.out:
                args.out.write_bytes(result)
            else:
                sys.stdout.buffer.write(result)
        else:
            print(json.dumps(verify(read(args.file)), sort_keys=True))
        return 0
    except (Refused, OSError, ValueError) as exc:
        print('{"status":"R18_10_REFUSED","authority":"none","live_xi_connected":false}',
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
