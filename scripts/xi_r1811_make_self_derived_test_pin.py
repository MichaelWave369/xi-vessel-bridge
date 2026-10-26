#!/usr/bin/env python3
"""Make an explicitly SELF-DERIVED UNTRUSTED public test pin.

Only for local CI demonstration: copying the key from a signed envelope is NOT
out-of-band trust, identity verification, Xi approval, or a safe production pin.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"reference"/"python"))
import xi_pin_policy_r1811 as pin
import xi_signed_receipt_r1810 as signed


def key_from_file(path):
    # Verifies signature math, but sender's public key is self-issued.
    signed.verify(signed.read(path))
    return json.loads(signed.read(path))["public_key_hex"]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-signed",type=Path,required=True)
    parser.add_argument("--revoked-from",type=Path)
    parser.add_argument("--epoch",type=int,default=1)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    key=key_from_file(args.from_signed)
    revoked=[key_from_file(args.revoked_from)] if args.revoked_from else []
    try:
        result=pin.make_test_policy(key,revoked,epoch=args.epoch)
    except (pin.Refused, ValueError):
        print("R18_11_TEST_POLICY_REFUSED",file=sys.stderr)
        return 2
    args.out.write_bytes(result)
    # Only the receipt's public self-issued key is copied, NEVER a secret.
    print("UNTRUSTED_TEST_PIN_WRITTEN_NO_IDENTITY_AUTHENTICATION")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
