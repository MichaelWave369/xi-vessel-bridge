"""R3 OFFLINE example: peer-pinned, signed, encrypted Xi/Phi fixture envelopes.

This is NOT Xi's native .xi/TESSERA codec, a live Room API, a credential
manager, or a deployed bridge. The wire shape is xi.phi.peer.fixture.r3,
local to this repository until both parties approve a real contract.
Requires the PyCA cryptography library. Do not use fixture keys in production.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = "xi.phi.peer.fixture.r3"
ALLOWED_KINDS = {"capsule.offer", "capsule.receipt"}
MAX_FRAME_BYTES = 16_384
MAX_PAYLOAD_BYTES = 8_192
MAX_TTL = 300
CLOCK_SKEW = 30
FRAME_FIELDS = {"version", "sender", "recipient", "stage", "request_id", "issued_at",
                "ttl", "ephemeral_public_key", "nonce", "ciphertext", "signature"}
PUBLIC_FIELDS = FRAME_FIELDS - {"ciphertext", "signature"}
PROVENANCE_FIELDS = {"author", "source", "version", "intended_use"}


class CrossingError(ValueError):
    """No error includes credentials, plaintext, or a private payload."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: object, size: int | None = None) -> bytes:
    if not isinstance(data, str) or len(data) > MAX_FRAME_BYTES * 2:
        raise CrossingError("invalid_base64")
    try:
        decoded = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CrossingError("invalid_base64") from exc
    if size is not None and len(decoded) != size:
        raise CrossingError("invalid_field_size")
    return decoded


def _uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def validate_payload(payload: object) -> dict:
    if not isinstance(payload, dict) or payload.get("kind") not in ALLOWED_KINDS:
        raise CrossingError("unsupported_payload")
    if payload["kind"] == "capsule.offer":
        if set(payload) != {"kind", "xi_text", "ast", "provenance", "xi_sha256"}:
            raise CrossingError("invalid_capsule_fields")
        xi = payload["xi_text"]
        if not isinstance(xi, str) or not 1 <= len(xi.encode("utf-8")) <= 4096:
            raise CrossingError("invalid_xi_text")
        if not isinstance(payload["ast"], dict):
            raise CrossingError("invalid_ast")
        provenance = payload["provenance"]
        if (not isinstance(provenance, dict) or set(provenance) != PROVENANCE_FIELDS
                or any(not isinstance(v, str) or not 1 <= len(v) <= 200 for v in provenance.values())):
            raise CrossingError("invalid_provenance")
        if payload["xi_sha256"] != hashlib.sha256(xi.encode("utf-8")).hexdigest():
            raise CrossingError("xi_hash_mismatch")
    else:
        if set(payload) != {"kind", "in_reply_to", "offered_payload_sha256", "decision"}:
            raise CrossingError("invalid_receipt_fields")
        if (not _uuid(payload["in_reply_to"])
                or not isinstance(payload["offered_payload_sha256"], str)
                or len(payload["offered_payload_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in payload["offered_payload_sha256"])
                or payload["decision"] != "fixture_verified"):
            raise CrossingError("invalid_receipt")
    if len(canonical(payload)) > MAX_PAYLOAD_BYTES:
        raise CrossingError("payload_too_large")
    return payload


def make_offer(xi_text: str, ast: dict, provenance: dict) -> dict:
    return validate_payload({"kind": "capsule.offer", "xi_text": xi_text, "ast": ast,
                             "provenance": provenance,
                             "xi_sha256": hashlib.sha256(xi_text.encode("utf-8")).hexdigest()})


def make_receipt(offer_request_id: str, offered_payload: dict) -> dict:
    validate_payload(offered_payload)
    if offered_payload["kind"] != "capsule.offer":
        raise CrossingError("receipt_target_not_offer")
    return validate_payload({"kind": "capsule.receipt", "in_reply_to": offer_request_id,
                             "offered_payload_sha256": hashlib.sha256(canonical(offered_payload)).hexdigest(),
                             "decision": "fixture_verified"})


@dataclass(frozen=True)
class PeerIdentity:
    """Public trust anchor explicitly pinned outside the incoming envelope."""
    sign_public: Ed25519PublicKey
    decrypt_public: X25519PublicKey


@dataclass(frozen=True)
class LocalKeys:
    sign_private: Ed25519PrivateKey
    decrypt_private: X25519PrivateKey

    @classmethod
    def fresh_fixture(cls) -> "LocalKeys":
        """In-memory disposable demo identity only."""
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    def public(self) -> PeerIdentity:
        return PeerIdentity(self.sign_private.public_key(), self.decrypt_private.public_key())


def public_bytes(key) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw)


def _derive_key(shared_secret: bytes, header: dict) -> bytes:
    # Bind the one-time ECDH exchange to sender, recipient, stage and request.
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=hashlib.sha256(canonical(header)).digest(),
                info=b"xi-phi-r3-fixture-aesgcm-v1").derive(shared_secret)


def seal(payload: dict, *, sender: str, recipient: str, stage: str,
         sender_keys: LocalKeys, recipient_public: PeerIdentity,
         issued_at: int | None = None, ttl: int = 120,
         request_id: str | None = None) -> dict:
    """Seal a synthetic fixture for an independently pinned test peer."""
    validate_payload(payload)
    if (not sender or not recipient or sender == recipient or not stage
            or any(not isinstance(v, str) or len(v) > 100 for v in (sender, recipient, stage))):
        raise CrossingError("invalid_peer_scope")
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
        raise CrossingError("invalid_ttl")
    at = int(time.time()) if issued_at is None else issued_at
    if type(at) is not int or at <= 0:
        raise CrossingError("invalid_issued_at")
    rid = str(uuid4()) if request_id is None else request_id
    if not _uuid(rid):
        raise CrossingError("invalid_request_id")
    ephemeral = X25519PrivateKey.generate()
    header = {"version": VERSION, "sender": sender, "recipient": recipient,
              "stage": stage, "request_id": rid, "issued_at": at, "ttl": ttl,
              "ephemeral_public_key": _b64(public_bytes(ephemeral.public_key())),
              "nonce": _b64(os.urandom(12))}
    key = _derive_key(ephemeral.exchange(recipient_public.decrypt_public), header)
    ciphertext = AESGCM(key).encrypt(_unb64(header["nonce"]), canonical(payload), canonical(header))
    unsigned = {**header, "ciphertext": _b64(ciphertext)}
    signature = sender_keys.sign_private.sign(canonical(unsigned))
    frame = {**unsigned, "signature": _b64(signature)}
    if len(canonical(frame)) > MAX_FRAME_BYTES:
        raise CrossingError("frame_too_large")
    return frame


class ReplayStore:
    """Persistent atomic replay refusal. No decrypted text is persisted."""
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("CREATE TABLE IF NOT EXISTS seen (sender TEXT NOT NULL, request_id TEXT NOT NULL, "
                        "frame_sha256 TEXT NOT NULL, PRIMARY KEY(sender, request_id))")

    def reserve(self, sender: str, request_id: str, frame_sha256: str) -> None:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT frame_sha256 FROM seen WHERE sender=? AND request_id=?",
                                  (sender, request_id)).fetchone()
            if row is not None:
                raise CrossingError("replay_rejected" if row[0] == frame_sha256 else "request_id_conflict")
            self.db.execute("INSERT INTO seen VALUES (?, ?, ?)", (sender, request_id, frame_sha256))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self.db.close()


class FixtureReceiver:
    def __init__(self, *, own_id: str, own_keys: LocalKeys, pinned_peers: dict[str, PeerIdentity],
                 stage: str, store: ReplayStore, pause_file: str | None = None,
                 clock: Callable[[], int] | None = None):
        if not own_id or not stage or not pinned_peers or own_id in pinned_peers:
            raise ValueError("invalid_receiver_configuration")
        self.own_id, self.keys, self.peers, self.stage = own_id, own_keys, pinned_peers, stage
        self.store, self.pause_file, self.clock = store, pause_file, clock or (lambda: int(time.time()))

    def open(self, frame: object) -> dict:
        # Pause first, including before idempotency checks and error detail.
        if self.pause_file is not None:
            try:
                if Path(self.pause_file).exists():
                    raise CrossingError("bridge_paused")
            except OSError as exc:
                raise CrossingError("pause_check_failed") from exc
        if not isinstance(frame, dict) or set(frame) != FRAME_FIELDS:
            raise CrossingError("invalid_frame_shape")
        try:
            raw_frame = canonical(frame)
        except (TypeError, ValueError) as exc:
            raise CrossingError("invalid_frame_shape") from exc
        if len(raw_frame) > MAX_FRAME_BYTES:
            raise CrossingError("frame_too_large")
        if (frame["version"] != VERSION or frame["recipient"] != self.own_id
                or frame["stage"] != self.stage):
            raise CrossingError("scope_denied")
        sender = frame["sender"]
        if not isinstance(sender, str) or sender not in self.peers:
            raise CrossingError("untrusted_sender")
        if not _uuid(frame["request_id"]):
            raise CrossingError("invalid_request_id")
        if type(frame["issued_at"]) is not int or type(frame["ttl"]) is not int or not 1 <= frame["ttl"] <= MAX_TTL:
            raise CrossingError("invalid_timestamp")
        now = self.clock()
        if frame["issued_at"] > now + CLOCK_SKEW or frame["issued_at"] + frame["ttl"] < now:
            raise CrossingError("expired_or_future_frame")
        header = {k: frame[k] for k in PUBLIC_FIELDS}
        unsigned = {**header, "ciphertext": frame["ciphertext"]}
        try:
            self.peers[sender].sign_public.verify(_unb64(frame["signature"], 64), canonical(unsigned))
        except InvalidSignature as exc:
            raise CrossingError("invalid_signature") from exc
        ephemeral_public = X25519PublicKey.from_public_bytes(_unb64(frame["ephemeral_public_key"], 32))
        nonce = _unb64(frame["nonce"], 12)
        ciphertext = _unb64(frame["ciphertext"])
        if len(ciphertext) < 16 or len(ciphertext) > MAX_PAYLOAD_BYTES + 16:
            raise CrossingError("invalid_ciphertext_size")
        key = _derive_key(self.keys.decrypt_private.exchange(ephemeral_public), header)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, canonical(header))
        except InvalidTag as exc:
            raise CrossingError("decryption_failed") from exc
        try:
            payload = json.loads(plaintext, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            validate_payload(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            raise CrossingError("invalid_decrypted_payload") from exc
        self.store.reserve(sender, frame["request_id"], hashlib.sha256(raw_frame).hexdigest())
        # Caller must handle any further approved work; no tool call is made here.
        return {"request_id": frame["request_id"], "sender": sender, "payload": payload,
                "payload_sha256": hashlib.sha256(canonical(payload)).hexdigest(),
                "local_only": True}
