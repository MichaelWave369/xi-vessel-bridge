#!/usr/bin/env python3
"""R18.11 offline fixture-only public-key pin / revoke simulation.

The expected key MUST be supplied in a separate local policy file. Its origin
is explicitly UNAUTHENTICATED, so pin matching establishes no real Xi identity.
No persistence, network, consent, delegated rights, or real key provisioning.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys

import xi_receipt_r189 as base
import xi_signed_receipt_r1810 as signed

SCHEMA = "PhiXi.R18_11_SimulatedLocalPinPolicy.v1"
REPORT = "PhiXi.R18_11_LocalPinVerificationReport.v1"
SOURCE = "LOCAL_TEST_KEY_COPY_NOT_INDEPENDENTLY_AUTHENTICATED"
SCOPE = "R18_10_SYNTHETIC_RECEIPT_MATH_ONLY"
FIELDS = frozenset({
    "schema", "policy_source", "epoch", "active_public_key_hex",
    "revoked_public_key_hexes", "scope", "external_identity_verified",
    "operator_approvals", "approved_operations", "live_xi_connected", "authority"
})
KEY = re.compile(r"^[0-9a-f]{64}$")
LIMIT = 4096


class Refused(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Refused(why)


def unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj


def _no_other_number(_):
    raise Refused("invalid number type")


def parse_policy(data: bytes):
    require(type(data) is bytes and 0 < len(data) <= LIMIT, "invalid policy size")
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=unique_pairs,
                           parse_float=_no_other_number, parse_constant=_no_other_number)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused("invalid policy JSON") from exc
    require(type(value) is dict and set(value) == FIELDS, "unreviewed policy fields")
    require(data == base.canonical(value), "policy is not canonical")
    require(value["schema"] == SCHEMA and value["policy_source"] == SOURCE
            and value["scope"] == SCOPE, "unreviewed policy source or scope")
    require(type(value["epoch"]) is int and 1 <= value["epoch"] <= 65535,
            "invalid simulated policy epoch")
    require(value["external_identity_verified"] is False and
            type(value["operator_approvals"]) is int and value["operator_approvals"] == 0 and
            type(value["approved_operations"]) is int and value["approved_operations"] == 0 and
            value["live_xi_connected"] is False and value["authority"] == "none",
            "simulated policy attempted authority promotion")
    pin = value["active_public_key_hex"]
    require(type(pin) is str and KEY.fullmatch(pin) is not None, "bad expected pin")
    revoked = value["revoked_public_key_hexes"]
    require(type(revoked) is list and len(revoked) <= 8 and
            all(type(k) is str and KEY.fullmatch(k) is not None for k in revoked)
            and revoked == sorted(set(revoked)) and pin not in revoked,
            "invalid revocation roster")
    return value


def make_test_policy(active_hex, revoked=(), epoch=1):
    # This fixture builder accepts ONLY operator-supplied test public bytes.
    # It does not authenticate how the public key was obtained.
    value = {
        "schema": SCHEMA,
        "policy_source": SOURCE,
        "epoch": epoch,
        "active_public_key_hex": active_hex,
        "revoked_public_key_hexes": sorted(revoked),
        "scope": SCOPE,
        "external_identity_verified": False,
        "operator_approvals": 0,
        "approved_operations": 0,
        "live_xi_connected": False,
        "authority": "none",
    }
    raw = base.canonical(value)
    parse_policy(raw)
    return raw


def verify(envelope: bytes, policy: bytes):
    # IMPORTANT: mathematically verify the self-issued signature first. This
    # still does not prove public-key identity or trust origin.
    signed_report = signed.verify(envelope)
    checked = parse_policy(policy)
    # signed.verify() already insists exact envelope schema, suite, and bytes.
    obj = json.loads(envelope.decode("ascii"))
    key = obj["public_key_hex"]
    require(key not in checked["revoked_public_key_hexes"], "key revoked locally")
    require(hmac.compare_digest(bytes.fromhex(key),
                                bytes.fromhex(checked["active_public_key_hex"])),
            "valid signature from a different public key")
    return {
        "schema": REPORT,
        "status": "LOCAL_SIMULATED_PIN_MATCH_AND_SIGNATURE_VALID_ONLY",
        "case_id": signed_report["case_id"],
        "policy_epoch": checked["epoch"],
        "test_pin_sha256": hashlib.sha256(bytes.fromhex(key)).hexdigest(),
        "signature_mathematically_valid": True,
        "simulated_local_pin_matched": True,
        "independent_partner_identity_verified": False,
        "out_of_band_key_authentication_verified": False,
        "operator_approvals": 0,
        "approved_operations": 0,
        "external_gates_promoted": 0,
        "real_two_host_crossing_tested": False,
        "live_xi_connected": False,
        "authority": "none",
    }


def read(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 8192,
            "invalid file or symlink")
    data = p.read_bytes()
    require(len(data) <= 8192, "file changed while reading")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    check = sub.add_parser("verify")
    check.add_argument("--file", type=Path, required=True)
    check.add_argument("--policy", type=Path, required=True)
    sub.add_parser("require-live")
    args = parser.parse_args(argv)
    if args.action == "require-live":
        print('{"status":"LIVE_AUTHORITY_REFUSED","authority":"none"}')
        return 2
    try:
        result = verify(read(args.file), read(args.policy))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Refused, signed.Refused, base.Refused, OSError, ValueError, KeyError, TypeError):
        print('{"status":"R18_11_PIN_REFUSED","authority":"none","live_xi_connected":false}',
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
