"""R5 local operator-authorized *fixture grants*. No Xi credential handling.

One independent cryptographically pinned peer is not automatically entitled to
send capsules. This extra authorization reads a constrained, local-only policy
file on EVERY received request. It runs after signature/AEAD verification and
BEFORE the replay ledger reserves a request ID or returns a receipt.

The JSON file is controlled by the local OS account, not cryptographically
signed. This is an offline authorization experiment, NOT a hardened policy
service or proof of identity. Never put real Xi tessera keys in this file.
"""
from __future__ import annotations

import os
import re
import stat
import uuid
from pathlib import Path

from xi_peer_r3 import CrossingError
from xi_peer_r4_http import strict_json

SCHEMA = "xi.phi.grant.fixture.r5"
POLICY_FIELDS = {
    "schema", "grant_id", "sender", "recipient", "stage",
    "capabilities", "not_before", "expires_at", "revoked",
}
CAPABILITY = "capsule.offer"
MAX_POLICY_BYTES = 2_048
MAX_GRANT_SECONDS = 600


def fixture_grant(*, sender: str, recipient: str, stage: str,
                  not_before: int, expires_at: int, revoked: bool = False) -> dict:
    """Create synthetic operator policy only; does NOT grant real access."""
    grant = {
        "schema": SCHEMA, "grant_id": str(uuid.uuid4()),
        "sender": sender, "recipient": recipient, "stage": stage,
        "capabilities": [CAPABILITY], "not_before": not_before,
        "expires_at": expires_at, "revoked": revoked,
    }
    validate_grant(grant)
    return grant


def validate_grant(data: object) -> dict:
    if not isinstance(data, dict) or set(data) != POLICY_FIELDS or data["schema"] != SCHEMA:
        raise CrossingError("grant_invalid")
    try:
        if str(uuid.UUID(data["grant_id"])) != data["grant_id"]:
            raise CrossingError("grant_invalid")
    except (ValueError, AttributeError, TypeError, KeyError) as exc:
        raise CrossingError("grant_invalid") from exc
    for field in ("sender", "recipient", "stage"):
        val = data[field]
        if not isinstance(val, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,100}", val):
            raise CrossingError("grant_invalid")
    if data["sender"] == data["recipient"]:
        raise CrossingError("grant_invalid")
    if data["capabilities"] != [CAPABILITY] or data["revoked"] not in (True, False) or type(data["revoked"]) is not bool:
        raise CrossingError("grant_invalid")
    start, end = data["not_before"], data["expires_at"]
    if (type(start) is not int or type(end) is not int or start <= 0
            or end <= start or end - start > MAX_GRANT_SECONDS):
        raise CrossingError("grant_invalid")
    return data


def read_operator_grant(path: str) -> dict:
    """Load one exact, small policy. Refuse missing, symlink and group-writable files."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        if Path(path).is_symlink():
            raise CrossingError("grant_invalid")
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise CrossingError("grant_missing") from exc
    except OSError as exc:
        raise CrossingError("grant_invalid") from exc
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or not 1 <= meta.st_size <= MAX_POLICY_BYTES
                or (os.name == "posix" and meta.st_mode & 0o022)):
            raise CrossingError("grant_invalid")
        raw = os.read(fd, MAX_POLICY_BYTES + 1)
    finally:
        os.close(fd)
    try:
        return validate_grant(strict_json(raw))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise CrossingError("grant_invalid") from exc


class OperatorGrantGate:
    def __init__(self, path: str):
        if not isinstance(path, str) or not path:
            raise ValueError("explicit grant file path required")
        self.path = path

    def __call__(self, sender: str, recipient: str, stage: str,
                 operation: str, now: int) -> None:
        # Filesystem policy is intentionally reloaded for every opened frame:
        # operator changes apply without restarting either process.
        grant = read_operator_grant(self.path)
        if (grant["sender"] != sender or grant["recipient"] != recipient
                or grant["stage"] != stage or operation not in grant["capabilities"]):
            raise CrossingError("grant_scope_denied")
        if grant["revoked"]:
            raise CrossingError("grant_revoked")
        if not grant["not_before"] <= now < grant["expires_at"]:
            raise CrossingError("grant_expired_or_not_yet_valid")


def atomic_write_fixture_grant(path: str, grant: dict) -> None:
    """Demo helper, safe replacement within an operator-owned private directory.

    It does not authenticate the operator or prevent filesystem owners changing
    a revoked grant back to active. Production revocation needs a proper source
    of authority, tamper-evident record and secure distribution.
    """
    import json
    validate_grant(grant)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = target.parent / (target.name + "." + uuid.uuid4().hex + ".tmp")
    payload = json.dumps(grant, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)
