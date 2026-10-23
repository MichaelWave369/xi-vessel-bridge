#!/usr/bin/env python3
"""R7 public witness kit: export and VERIFY synthetic peer crossing evidence.

No real Xi network connection, tessera, bearer grant, native Xi AST parsing or
private key is used or exported. Public verification proves signed test bytes
relative to keys INSIDE THE BUNDLE, NOT that Hunter issued those keys.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from xi_peer_r3 import (
    FRAME_FIELDS, PUBLIC_FIELDS, VERSION, CrossingError, FixtureReceiver,
    LocalKeys, ReplayStore, _unb64, canonical, make_offer, make_receipt,
    public_bytes, seal, validate_payload, _derive_key,
)
from xi_peer_r4_http import strict_json

KIT_VERSION = "xi.phi.witness.public.fixture.r7"
MAX_KIT_BYTES = 80_000
KIT_FIELDS = {
    "kit_version", "scope", "self_signed_fixture", "live_xi_connected",
    "peers", "synthetic_offer", "synthetic_receipt",
    "offer_payload_sha256", "receipt_payload_sha256",
    "offer_frame", "receipt_frame", "negative_vectors",
}
PEER_FIELDS = {"sign_public_b64", "decrypt_public_b64"}
NEGATIVE_FIELDS = {"bad_offer_signature", "bad_offer_ciphertext", "bad_receipt_signature"}
STAGE = "r7-public-evidence-fixture"


def digest(value: dict) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _b64_public(key) -> str:
    import base64
    return base64.b64encode(public_bytes(key)).decode("ascii")


def _fixture_peers() -> tuple[LocalKeys, LocalKeys, dict]:
    phi, xi = LocalKeys.fresh_fixture(), LocalKeys.fresh_fixture()
    public = {
        "phi-fixture": {
            "sign_public_b64": _b64_public(phi.sign_private.public_key()),
            "decrypt_public_b64": _b64_public(phi.decrypt_private.public_key()),
        },
        "xi-fixture": {
            "sign_public_b64": _b64_public(xi.sign_private.public_key()),
            "decrypt_public_b64": _b64_public(xi.decrypt_private.public_key()),
        },
    }
    return phi, xi, public


def build_kit(*, disclose_synthetic_content_keys: bool = False):
    """Generate disposable identities; optionally return two frame-only AEAD keys.

    R7 default remains public-keys-only. R8 opt-in discloses **only** symmetric
    per-message fixture content keys for independent plaintext verification.
    Never use the disclosure mode with confidential or real Xi messages.
    """
    phi_keys, xi_keys, public = _fixture_peers()
    offer = make_offer(
        "⟨ Ξ ⋈ Φ ⟩",
        {"kind": "synthetic-fixture-AST", "systems": [
            "xi-vessel-bridge", "Commonline", "FieldAccord", "think-tank"]},
        {"author": "phi-fixture", "source": "public-witness-fixture",
         "version": "r7", "intended_use": "public non-secret conformance exchange"},
    )
    now = int(time.time())
    phi_store, xi_store = ReplayStore(":memory:"), ReplayStore(":memory:")
    try:
        xi = FixtureReceiver(
            own_id="xi-fixture", own_keys=xi_keys,
            pinned_peers={"phi-fixture": phi_keys.public()},
            stage=STAGE, store=xi_store, clock=lambda: now)
        phi = FixtureReceiver(
            own_id="phi-fixture", own_keys=phi_keys,
            pinned_peers={"xi-fixture": xi_keys.public()},
            stage=STAGE, store=phi_store, clock=lambda: now)
        offer_frame = seal(
            offer, sender="phi-fixture", recipient="xi-fixture", stage=STAGE,
            sender_keys=phi_keys, recipient_public=xi_keys.public(), issued_at=now)
        received = xi.open(offer_frame)
        receipt = make_receipt(received["request_id"], received["payload"])
        receipt_frame = seal(
            receipt, sender="xi-fixture", recipient="phi-fixture", stage=STAGE,
            sender_keys=xi_keys, recipient_public=phi_keys.public(), issued_at=now)
        confirmed = phi.open(receipt_frame)
        if confirmed["payload"] != receipt:
            raise CrossingError("fixture_round_trip_failed")
    finally:
        phi_store.close()
        xi_store.close()

    bad_signature = copy.deepcopy(offer_frame)
    import base64
    bad_signature["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    bad_ciphertext = copy.deepcopy(offer_frame)
    raw = bytearray(_unb64(bad_ciphertext["ciphertext"]))
    raw[0] ^= 1
    bad_ciphertext["ciphertext"] = base64.b64encode(raw).decode("ascii")
    bad_receipt_signature = copy.deepcopy(receipt_frame)
    bad_receipt_signature["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    kit = {
        "kit_version": KIT_VERSION,
        "scope": "public_only_synthetic_fixture_no_live_xi",
        "self_signed_fixture": True,
        "live_xi_connected": False,
        "peers": public,
        "synthetic_offer": offer,
        "synthetic_receipt": receipt,
        "offer_payload_sha256": digest(offer),
        "receipt_payload_sha256": digest(receipt),
        "offer_frame": offer_frame,
        "receipt_frame": receipt_frame,
        "negative_vectors": {
            "bad_offer_signature": bad_signature,
            "bad_offer_ciphertext": bad_ciphertext,
            "bad_receipt_signature": bad_receipt_signature,
        },
    }
    verify_kit(kit)
    if not disclose_synthetic_content_keys:
        return kit

    def disclose_content_key(frame: dict, receiver: LocalKeys) -> str:
        # Compute only the one-message AEAD key. Recipient private X25519 and
        # long-term Ed25519 signing keys are never exported or serialized.
        eph = X25519PublicKey.from_public_bytes(_unb64(frame["ephemeral_public_key"], 32))
        header = {k: frame[k] for k in PUBLIC_FIELDS}
        key = _derive_key(receiver.decrypt_private.exchange(eph), header)
        return base64.b64encode(key).decode("ascii")

    return kit, {
        "offer_aesgcm_key_b64": disclose_content_key(offer_frame, xi_keys),
        "receipt_aesgcm_key_b64": disclose_content_key(receipt_frame, phi_keys),
    }


def verify_frame_signature(frame: object, peers: dict) -> None:
    """Public verification of signature, not decryption or remote authorship."""
    if not isinstance(frame, dict) or set(frame) != FRAME_FIELDS:
        raise CrossingError("invalid_frame_shape")
    if frame["version"] != VERSION:
        raise CrossingError("invalid_frame_version")
    sender = frame["sender"]
    if not isinstance(sender, str) or sender not in peers:
        raise CrossingError("unknown_fixture_signer")
    if len(canonical(frame)) > 16_384:
        raise CrossingError("frame_too_large")
    key = Ed25519PublicKey.from_public_bytes(_unb64(peers[sender]["sign_public_b64"], 32))
    unsigned = {k: v for k, v in frame.items() if k != "signature"}
    try:
        key.verify(_unb64(frame["signature"], 64), canonical(unsigned))
    except InvalidSignature as exc:
        raise CrossingError("public_signature_invalid") from exc


def verify_kit(kit: object) -> dict:
    """Verify public signatures + disclosed synthetic payload binding and negatives.

    Zero private decryption keys available to verifier. Test ciphertext cannot
    be decrypted by an unaffiliated third party with this evidence package.
    """
    try:
        if not isinstance(kit, dict) or set(kit) != KIT_FIELDS:
            raise CrossingError("kit_invalid_shape")
        if (kit["kit_version"] != KIT_VERSION or
                kit["scope"] != "public_only_synthetic_fixture_no_live_xi" or
                kit["self_signed_fixture"] is not True or
                kit["live_xi_connected"] is not False):
            raise CrossingError("kit_invalid_scope")
        peers = kit["peers"]
        if not isinstance(peers, dict) or set(peers) != {"xi-fixture", "phi-fixture"}:
            raise CrossingError("kit_invalid_peers")
        for p in peers.values():
            if not isinstance(p, dict) or set(p) != PEER_FIELDS:
                raise CrossingError("kit_invalid_peers")
            _unb64(p["sign_public_b64"], 32)
            _unb64(p["decrypt_public_b64"], 32)
        offer = validate_payload(kit["synthetic_offer"])
        receipt = validate_payload(kit["synthetic_receipt"])
        if offer["kind"] != "capsule.offer" or receipt["kind"] != "capsule.receipt":
            raise CrossingError("kit_invalid_payload_kind")
        if kit["offer_payload_sha256"] != digest(offer):
            raise CrossingError("offer_digest_mismatch")
        if kit["receipt_payload_sha256"] != digest(receipt):
            raise CrossingError("receipt_digest_mismatch")
        proposal, answer = kit["offer_frame"], kit["receipt_frame"]
        for f in (proposal, answer):
            verify_frame_signature(f, peers)
            if f["stage"] != STAGE:
                raise CrossingError("kit_wrong_stage")
        if (proposal["sender"], proposal["recipient"]) != ("phi-fixture", "xi-fixture"):
            raise CrossingError("kit_wrong_offer_route")
        if (answer["sender"], answer["recipient"]) != ("xi-fixture", "phi-fixture"):
            raise CrossingError("kit_wrong_receipt_route")
        if (receipt["in_reply_to"] != proposal["request_id"] or
                receipt["offered_payload_sha256"] != digest(offer)):
            raise CrossingError("kit_unbound_receipt")
        if answer["request_id"] == proposal["request_id"]:
            raise CrossingError("kit_duplicate_request_id")
        negatives = kit["negative_vectors"]
        if not isinstance(negatives, dict) or set(negatives) != NEGATIVE_FIELDS:
            raise CrossingError("kit_invalid_negative_controls")
        for name, expected in [
            ("bad_offer_signature", proposal),
            ("bad_offer_ciphertext", proposal),
            ("bad_receipt_signature", answer),
        ]:
            broken = negatives[name]
            if not isinstance(broken, dict) or set(broken) != FRAME_FIELDS or broken == expected:
                raise CrossingError("kit_invalid_negative_control")
            try:
                verify_frame_signature(broken, peers)
            except CrossingError as exc:
                if str(exc) != "public_signature_invalid":
                    raise CrossingError("kit_negative_wrong_failure") from exc
            else:
                raise CrossingError("kit_negative_unexpected_pass")
        return {
            "status": "R7_PUBLIC_WITNESS_VERIFIED",
            "public_signatures_verified": 2,
            "tampered_vectors_rejected": 3,
            "payload_and_receipt_binding_verified": True,
            "self_signed_fixture": True,
            "live_xi_connected": False,
            "decryption_checked_by_public_verifier": False,
        }
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, CrossingError):
            raise
        raise CrossingError("kit_invalid_input") from exc


def read_kit(path: str) -> dict:
    raw = Path(path).read_bytes()
    if not raw or len(raw) > MAX_KIT_BYTES:
        raise CrossingError("kit_file_size_invalid")
    try:
        kit = strict_json(raw)
        return kit
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CrossingError("kit_invalid_json") from exc


def main():
    p = argparse.ArgumentParser(description="Public-only offline Xi/Phi witness kit")
    sub = p.add_subparsers(dest="action", required=True)
    export = sub.add_parser("export", help="export synthetic test bundle, NO PRIVATE KEYS")
    export.add_argument("--out", required=True)
    verify = sub.add_parser("verify", help="verify public bundle offline, no Xi access")
    verify.add_argument("--file", required=True)
    args = p.parse_args()
    try:
        if args.action == "export":
            path = Path(args.out)
            if path.is_symlink() or path.exists():
                raise CrossingError("refuse_overwrite_or_symlink")
            kit = build_kit()
            path.parent.mkdir(parents=True, exist_ok=True)
            # World-readable by design: this is PUBLIC test material, no keys.
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, "wb") as file:
                file.write(canonical(kit) + b"\n")
            result = verify_kit(read_kit(str(path)))
        else:
            result = verify_kit(read_kit(args.file))
        print(json.dumps(result, sort_keys=True, indent=2))
    except (CrossingError, OSError) as exc:
        p.error(str(exc) if isinstance(exc, CrossingError) else "filesystem_error")


if __name__ == "__main__":
    main()
