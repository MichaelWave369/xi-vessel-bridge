#!/usr/bin/env python3
"""R18.9 public *illustrative* receipt bytes: strict ASCII JSON parity, not Xi auth.

This frozen subset is a candidate between languages, NOT RFC 8785 (JCS),
an Xi-native schema, actual signed receipt, observed computation, peer identity,
transport, independent partner approval, or a real pilot. Nothing executes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import xi_pilot_r18 as r18

SCHEMA = "PhiXi.R18_9_PublicIllustrativeReceipt.v1"
PROFILE = "PhiXi.R18_9.ASCII_SORTED_JSON.v1"
CHECK_SCHEMA = "PhiXi.R18_9_CanonicalReceiptCheck.v1"
CASES = {
    "digest": "SYNTHETIC_DIGEST_REVIEW_ONLY",
    "policy": "SYNTHETIC_POLICY_DENIAL_REVIEW_ONLY",
    "replay": "SYNTHETIC_REPLAY_DENIAL_REVIEW_ONLY",
    "revoked": "SYNTHETIC_REVOCATION_REVIEW_ONLY",
}
MAX_BYTES = 4096
ASCII = re.compile(r"^[\x20-\x7e]*$")


class Refused(ValueError):
    """Reject a noncanonical document or any claimed approval."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def canonical(value):
    """Deliberately restricted ASCII JSON: objects sorted, compact, LF-terminated.

    No floats, null, Unicode, timestamps, user strings or arbitrary extensions.
    Unlike JCS, this profile does not define general number or Unicode handling.
    """
    def check(v):
        if type(v) is dict:
            require(all(type(k) is str and ASCII.fullmatch(k) for k in v),
                    "non-ASCII key")
            for child in v.values():
                check(child)
        elif type(v) is list:
            for child in v:
                check(child)
        elif type(v) is str:
            require(ASCII.fullmatch(v) is not None, "non-ASCII or control string")
        elif type(v) is int:
            require(0 <= v <= 9007199254740991, "integer outside safe range")
        else:
            require(type(v) is bool, "unsupported JSON type")
    check(value)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    require(len(raw) <= MAX_BYTES, "receipt too large")
    return raw


def make(case):
    require(case in CASES, "unknown candidate scenario")
    payload = r18.PAYLOAD
    require(len(payload) == 88 and r18.sha(payload) ==
            "8370bdb1f706a2168accc1c225a37c98ec907cd3e954b67c1cdcc9d8ddd8feb5",
            "source payload identity changed")
    return {
        "schema": SCHEMA,
        "canonical_profile": PROFILE,
        "case_id": case,
        "review_label": CASES[case],
        "subject": {
            "origin": "PHI369-local-synthetic-fixture",
            "classification": "synthetic_public",
            "operation": "artifact.sha256",
            "bytes": len(payload),
            "sha256": r18.sha(payload),
        },
        "parties": ["phi-sim", "xi-sim"],
        "example_only": True,
        "observed_exchange": False,
        "independent_signatures_verified": 0,
        "operator_approvals": 0,
        "approved_operations": 0,
        "r17_external_pilot": "BLOCKED",
        "r18_real_two_host_pilot": "NOT_RUN",
        "live_xi_connected": False,
        "authority": "none",
    }


def emit(case):
    return canonical(make(case))


def _unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate JSON key")
        out[key] = value
    return out


def _reject_number(_text):
    raise Refused("unsupported JSON number")


def verify(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_BYTES,
            "missing, excessive or non-byte receipt")
    try:
        obj = json.loads(data.decode("ascii"), object_pairs_hook=_unique,
                         parse_float=_reject_number, parse_constant=_reject_number)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused("non-ASCII or invalid JSON") from exc
    require(type(obj) is dict, "root must be object")
    case = obj.get("case_id")
    require(type(case) is str and case in CASES, "unknown case")
    expected = emit(case)
    require(data == expected, "noncanonical, mutated, extra or privileged receipt")
    # Exact byte identity guarantees type/value agreement; no blind hash trust.
    return {
        "schema": CHECK_SCHEMA,
        "status": "CANONICAL_BYTES_MATCH_UNAUTHENTICATED",
        "case_id": case,
        "sha256": hashlib.sha256(data).hexdigest(),
        "canonical_bytes": len(data),
        "independent_signatures_verified": 0,
        "approved_operations": 0,
        "live_xi_connected": False,
        "authority": "none",
    }


def read(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_BYTES,
            "missing, linked or oversized input")
    return p.read_bytes()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    gen = sub.add_parser("emit")
    gen.add_argument("--case", choices=CASES, required=True)
    gen.add_argument("--out", type=Path)
    check = sub.add_parser("verify")
    check.add_argument("--file", type=Path, required=True)
    sub.add_parser("require-live")
    args = parser.parse_args(argv)
    if args.action == "require-live":
        print('{"status":"LIVE_AUTHORITY_REFUSED","authority":"none"}')
        return 2
    try:
        if args.action == "emit":
            data = emit(args.case)
            if args.out:
                args.out.write_bytes(data)
            else:
                sys.stdout.buffer.write(data)
        else:
            print(json.dumps(verify(read(args.file)), sort_keys=True))
        return 0
    except (Refused, OSError, ValueError):
        print('{"status":"CANONICAL_RECEIPT_REFUSED","authority":"none","live_xi_connected":false}',
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
