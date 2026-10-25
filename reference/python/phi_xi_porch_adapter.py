#!/usr/bin/env python3
"""Offline, read-only PhiOS/GitPorch ↔ Xi evidence adapter.

No network, extraction, remote tool execution, private keys, or implicit grants.
A PhiXi.Relay.v0.1 signature is checked only against an OUT-OF-BAND pinned key.
This is NOT a deployed Xi endpoint or a production mirror.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import time

RELAY_SCHEMA = "PhiXi.Relay.v0.1"
INVENTORY_SCHEMA = "PhiXi.PorchInventory.v0.1"
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 128
MAX_ARCHIVE = 64 * 1024 * 1024
HEX256 = re.compile(r"^[0-9a-f]{64}$")
BASE_FIELDS = {"schema", "kind", "id", "from", "ts", "sig"}
KIND_FIELDS = {
    "announce": {"sha256", "size", "note"},
    "deliver": {"sha256", "size", "to", "via", "data"},
    "receipt": {"sha256", "received_sha256", "matched", "in_reply_to", "to"},
    "request": {"sha256", "to"},
}


class Refused(ValueError):
    """Input is untrusted, out of scope, or cannot be proved."""


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_stream(stream, limit=MAX_FILE) -> tuple[int, str]:
    h = hashlib.sha256()
    n = 0
    while True:
        block = stream.read(min(65536, limit + 1 - n))
        if not block:
            break
        n += len(block)
        if n > limit:
            raise Refused("file exceeds size limit")
        h.update(block)
    return n, h.hexdigest()


def inventory(root: Path) -> dict:
    """Hash explicitly chosen local regular files; never follow symlinks."""
    if root.is_symlink() or not root.is_dir():
        raise Refused("root must be a real, existing directory")
    root = root.resolve(strict=True)
    entries = []
    total = 0

    def visit(folder: Path):
        nonlocal total
        for ent in sorted(os.scandir(folder), key=lambda item: item.name):
            path = Path(ent.path)
            if ent.is_symlink():
                raise Refused("symlink in inventory: " + path.relative_to(root).as_posix())
            if ent.is_dir(follow_symlinks=False):
                visit(path)
            elif ent.is_file(follow_symlinks=False):
                if len(entries) >= MAX_FILES:
                    raise Refused("inventory file count exceeded")
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    with os.fdopen(fd, "rb") as stream:
                        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                            raise Refused("not a regular file")
                        size, sha = hash_stream(stream)
                except Exception:
                    # fdopen owns the descriptor after successful creation.
                    raise
                total += size
                if total > MAX_TOTAL:
                    raise Refused("inventory byte count exceeded")
                entries.append({"path": path.relative_to(root).as_posix(), "size_bytes": size, "sha256": sha})
            else:
                raise Refused("special file refused")
    visit(root)
    entries.sort(key=lambda row: row["path"])
    # Do not emit the root's absolute location or any contents.
    return {"schema": INVENTORY_SCHEMA, "status": "offline_local_observation",
            "file_count": len(entries), "total_bytes": total,
            "inventory_sha256": digest(canonical(entries)), "entries": entries,
            "authority": "none", "live_xi_connected": False}


def safe_member_name(raw: str) -> str:
    if not isinstance(raw, str) or not raw or raw.startswith("/") or "\\" in raw:
        raise Refused("unsafe tar member path")
    name = raw[2:] if raw.startswith("./") else raw
    if name in ("", "."):
        return ""
    if "//" in name or any(part in ("", ".", "..") for part in name.split("/")):
        raise Refused("unsafe tar member traversal")
    return PurePosixPath(name).as_posix()


def audit_bundle(archive: Path) -> dict:
    """Bounded byte-for-byte audit of README_PINS.json, without extraction."""
    if not archive.is_file() or archive.is_symlink() or archive.stat().st_size > MAX_ARCHIVE:
        raise Refused("archive missing, symlinked, or too large")
    with tarfile.open(archive, mode="r:gz") as tar:
        files = {}
        members = tar.getmembers()
        if len(members) > MAX_FILES + 40:
            raise Refused("archive has too many members")
        total = 0
        for member in members:
            name = safe_member_name(member.name)
            if member.isdir():
                continue
            if not member.isfile() or not name or name in files:
                raise Refused("unsupported, blank, or duplicate tar member")
            if member.size > MAX_FILE:
                raise Refused("oversized tar member")
            total += member.size
            if total > MAX_TOTAL:
                raise Refused("archive uncompressed limit exceeded")
            stream = tar.extractfile(member)
            if stream is None:
                raise Refused("unreadable tar member")
            with stream:
                size, sha = hash_stream(stream)
            if size != member.size:
                raise Refused("tar header/content size mismatch")
            files[name] = (size, sha)
        pin_member = next((m for m in members if safe_member_name(m.name) == "README_PINS.json" and m.isfile()), None)
        if pin_member is None or pin_member.size > 128 * 1024:
            raise Refused("missing bounded README_PINS.json")
        pin_stream = tar.extractfile(pin_member)
        if pin_stream is None:
            raise Refused("missing pin content")
        with pin_stream:
            pins = json.loads(pin_stream.read().decode("utf-8"))
        records = pins.get("files")
        if not isinstance(records, dict) or not records:
            raise Refused("invalid pin dictionary")
        if set(files) - {"README_PINS.json"} != set(records):
            raise Refused("manifest coverage mismatch")
        for name, fields in records.items():
            if safe_member_name(name) != name or not isinstance(fields, dict):
                raise Refused("invalid manifest member")
            actual = files[name]
            if type(fields.get("size_bytes")) is not int or fields["size_bytes"] != actual[0]:
                raise Refused("manifest size mismatch: " + name)
            if fields.get("sha256") != actual[1]:
                raise Refused("manifest hash mismatch: " + name)
        return {"status": "hashes_match_bundled_manifest",
                "manifest_sha256": files["README_PINS.json"][1],
                "verified_files": len(records), "archive_members": len(members),
                "authority": "self-declared-hashes-only",
                "executed": False, "extracted": False, "live_xi_connected": False}


def strict_b64(value: str) -> bytes:
    if not isinstance(value, str):
        raise Refused("base64 must be a string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refused("invalid base64") from exc


def read_pins(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    peers = data.get("peers")
    if not isinstance(peers, list) or not peers or len(peers) > 32:
        raise Refused("nonempty pinned peers list required")
    result = set()
    for peer in peers:
        key = peer.get("ed25519") if isinstance(peer, dict) else None
        if not isinstance(key, str) or not key.startswith("ed25519:"):
            raise Refused("invalid peer pin")
        if len(strict_b64(key[8:])) != 32 or key in result:
            raise Refused("invalid or duplicate peer key")
        result.add(key)
    return result


def inspect_relay(messages: list[dict], pins: set[str], now: int | None = None) -> dict:
    """Validate signed evidence; never interpret a request as an operation."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if now is None:
        now = int(time.time())
    if not isinstance(messages, list) or not 1 <= len(messages) <= 64:
        raise Refused("expected 1..64 messages")
    seen = set()
    output = []
    for msg in messages:
        if not isinstance(msg, dict):
            raise Refused("message is not an object")
        kind = msg.get("kind")
        if kind not in KIND_FIELDS:
            raise Refused("unknown kind")
        if set(msg) - (BASE_FIELDS | KIND_FIELDS[kind]) or BASE_FIELDS - set(msg):
            raise Refused("unknown or missing envelope fields")
        if msg["schema"] != RELAY_SCHEMA:
            raise Refused("wrong relay schema")
        if not isinstance(msg["id"], str) or not (1 <= len(msg["id"]) <= 128):
            raise Refused("invalid message id")
        if msg["id"] in seen:
            raise Refused("replayed message id within batch")
        seen.add(msg["id"])
        if type(msg["ts"]) is not int or abs(now - msg["ts"]) > 600:
            raise Refused("stale or invalid timestamp")
        peer = msg["from"]
        if not isinstance(peer, str) or peer not in pins:
            raise Refused("peer is not independently pinned")
        signature = strict_b64(msg["sig"])
        if len(signature) != 64:
            raise Refused("invalid signature length")
        try:
            Ed25519PublicKey.from_public_bytes(strict_b64(peer[8:])).verify(
                signature, canonical({key: val for key, val in msg.items() if key != "sig"}))
        except Exception as exc:
            raise Refused("signature verification failed") from exc
        sha = msg.get("sha256")
        if not isinstance(sha, str) or HEX256.fullmatch(sha) is None:
            raise Refused("invalid object digest")
        if kind == "request":
            raise Refused("remote requests never execute in the read-only adapter")
        if kind in ("announce", "deliver"):
            if type(msg.get("size")) is not int or not 0 <= msg["size"] <= MAX_FILE:
                raise Refused("size missing or out of bounds")
        if kind == "deliver":
            if msg.get("via") != "inline" or "data" not in msg:
                raise Refused("pointer-only delivery is not byte-verifiable")
            data = strict_b64(msg["data"])
            if len(data) != msg["size"] or digest(data) != sha:
                raise Refused("delivery bytes fail integrity check")
        if kind == "receipt":
            got = msg.get("received_sha256")
            matched = msg.get("matched")
            if not isinstance(got, str) or not HEX256.fullmatch(got):
                raise Refused("invalid received digest")
            if type(matched) is not bool or matched != (sha == got):
                raise Refused("contradictory receipt")
            if not isinstance(msg.get("in_reply_to"), str) or not msg["in_reply_to"]:
                raise Refused("receipt not bound to message id")
        output.append({"kind": kind, "id": msg["id"], "peer": peer,
                       "sha256": sha, "signature": "verified-against-local-pin",
                       "content": "verified" if kind == "deliver" else "not-transferred"})
    return {"status": "offline_signed_evidence_only", "messages_verified": len(output),
            "messages": output, "authority": "none",
            "replay_scope": "this-batch-only", "live_xi_connected": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    cmd = parser.add_subparsers(dest="action", required=True)
    cmd.add_parser("inventory").add_argument("--root", type=Path, required=True)
    cmd.add_parser("audit-bundle").add_argument("--archive", type=Path, required=True)
    r = cmd.add_parser("inspect-relay")
    r.add_argument("--pins", type=Path, required=True)
    r.add_argument("--messages", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "inventory":
            result = inventory(args.root)
        elif args.action == "audit-bundle":
            result = audit_bundle(args.archive)
        else:
            raw = json.loads(args.messages.read_text(encoding="utf-8"))
            result = inspect_relay(raw if isinstance(raw, list) else [raw], read_pins(args.pins))
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (Refused, OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "refused": str(exc), "live_xi_connected": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
