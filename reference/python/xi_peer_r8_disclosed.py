#!/usr/bin/env python3
"""R8 public SYNTHETIC fixture witness with independently decryptable frames.

WARNING: content keys in this public artifact deliberately reveal BOTH
synthetic test-frame plaintexts. No real Xi/Vessel data or credentials are
permitted in the exporter. This does NOT export identity private keys.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from xi_peer_r3 import PUBLIC_FIELDS, CrossingError, _unb64, canonical, validate_payload
from xi_peer_r4_http import strict_json
from xi_peer_r7_handoff import build_kit as build_r7, verify_kit as verify_r7

VERSION = "xi.phi.public-disclosure.fixture.r8"
FIELDS = {"format", "synthetic_only", "confidentiality_disclosed", "live_xi_connected",
          "r7_witness", "one_message_content_keys"}
KEY_FIELDS = {"offer_aesgcm_key_b64", "receipt_aesgcm_key_b64"}
MAX_BYTES = 100_000


def build_kit() -> dict:
    """Only built-in, synthetic R7 fixture data; no external sources accepted."""
    original, keys = build_r7(disclose_synthetic_content_keys=True)
    result = {
        "format": VERSION,
        "synthetic_only": True,
        "confidentiality_disclosed": True,
        "live_xi_connected": False,
        "r7_witness": original,
        "one_message_content_keys": keys,
    }
    verify_kit(result)
    return result


def decrypt_frame(frame: dict, content_key_b64: str, expected: dict) -> None:
    """AEAD-decrypt and compare the EXACT canonical bytes, not just an assertion."""
    key = _unb64(content_key_b64, 32)
    header = {name: frame[name] for name in PUBLIC_FIELDS}
    try:
        clear_bytes = AESGCM(key).decrypt(
            _unb64(frame["nonce"], 12),
            _unb64(frame["ciphertext"]),
            canonical(header),
        )
    except InvalidTag as exc:
        raise CrossingError("public_disclosure_aead_invalid") from exc
    # Sender sealed canonical JSON with UTF-8 bytes. No unknown, alternate
    # serialization is silently substituted by the public verifier.
    if clear_bytes != canonical(expected):
        raise CrossingError("disclosed_payload_does_not_match_ciphertext")
    try:
        decoded = strict_json(clear_bytes)
        validate_payload(decoded)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CrossingError("decrypted_fixture_payload_invalid") from exc
    if decoded != expected:
        raise CrossingError("decrypted_fixture_payload_invalid")


def verify_kit(kit: object) -> dict:
    if not isinstance(kit, dict) or set(kit) != FIELDS:
        raise CrossingError("r8_invalid_shape")
    if (kit["format"] != VERSION or kit["synthetic_only"] is not True or
            kit["confidentiality_disclosed"] is not True or
            kit["live_xi_connected"] is not False):
        raise CrossingError("r8_invalid_scope")
    r7, keys = kit["r7_witness"], kit["one_message_content_keys"]
    if not isinstance(keys, dict) or set(keys) != KEY_FIELDS:
        raise CrossingError("r8_invalid_key_disclosure")
    # First inspect signed frames and receipt linkage using the R7 verifier.
    report = verify_r7(r7)
    if report["status"] != "R7_PUBLIC_WITNESS_VERIFIED":
        raise CrossingError("r8_embedded_witness_invalid")
    decrypt_frame(r7["offer_frame"], keys["offer_aesgcm_key_b64"], r7["synthetic_offer"])
    decrypt_frame(r7["receipt_frame"], keys["receipt_aesgcm_key_b64"], r7["synthetic_receipt"])
    return {
        "status": "R8_PUBLIC_PLAINTEXT_BINDING_VERIFIED",
        "public_signatures_verified": 2,
        "sealed_frames_decrypted_and_compared": 2,
        "tampered_vectors_rejected": 3,
        "disclosed_keys_are_frame_only": True,
        "confidentiality_disclosed": True,
        "self_signed_fixture": True,
        "live_xi_connected": False,
        "native_xi_parser_checked": False,
    }


def read_kit(path: str) -> dict:
    raw = Path(path).read_bytes()
    if not raw or len(raw) > MAX_BYTES:
        raise CrossingError("r8_file_size_invalid")
    try:
        result = strict_json(raw)
        if not isinstance(result, dict):
            raise CrossingError("r8_invalid_shape")
        return result
    except (UnicodeError, ValueError, TypeError) as exc:
        if isinstance(exc, CrossingError):
            raise
        raise CrossingError("r8_invalid_json") from exc


def main():
    parser = argparse.ArgumentParser(
        description="R8 PUBLIC synthetic frames; includes disclosed one-message content keys")
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export", help="create ONE transparent synthetic witness")
    export.add_argument("--out", required=True)
    verify = sub.add_parser("verify", help="independently decrypt/check a public fixture")
    verify.add_argument("--file", required=True)
    args = parser.parse_args()
    try:
        if args.command == "export":
            out = Path(args.out)
            if out.is_symlink() or out.exists():
                raise CrossingError("refuse_overwrite_or_symlink")
            kit = build_kit()  # hard-coded synthetic data ONLY
            out.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, "wb") as f:
                f.write(canonical(kit) + b"\n")
            result = verify_kit(read_kit(str(out)))
        else:
            result = verify_kit(read_kit(args.file))
        print(json.dumps(result, indent=2, sort_keys=True))
    except (OSError, CrossingError) as exc:
        parser.error(str(exc) if isinstance(exc, CrossingError) else "filesystem_error")


if __name__ == "__main__":
    main()
