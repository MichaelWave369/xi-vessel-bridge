"""R6 OFFLINE ONLY: durable operator grant pinning and revocation tombstones.

Replaces R5's mutable JSON-only authorization *in the local test fixture*.
R6 prevents accidental same-ID scope changes and silent file rollback after a
revocation has been observed or committed. An operator/attacker able to alter
the SQLite DB or run new trusted code can bypass this: NO production claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Callable

from xi_peer_r3 import CrossingError, canonical
from xi_peer_r5_policy import (
    OperatorGrantGate, atomic_write_fixture_grant, read_operator_grant, validate_grant,
)


def immutable_grant_digest(grant: dict) -> str:
    """All authorization fields except mutable revocation state are immutable."""
    validate_grant(grant)
    return hashlib.sha256(canonical({k: v for k, v in grant.items() if k != "revoked"})).hexdigest()


class DurableGrantLedger:
    """SQLite grant-ID pin with monotonic active -> revoked transition.

    Each operation uses one immediate transaction; the tombstone is committed
    even if the caller later raises grant_revoked. SQLite is local-state
    durability, not a cryptographic/tamperproof record.
    """
    def __init__(self, path: str):
        if not isinstance(path, str) or not path:
            raise ValueError("explicit ledger path required")
        if path != ":memory:":
            parent = Path(path).expanduser().parent
            parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS grant_pins ("
            "grant_id TEXT PRIMARY KEY, immutable_sha256 TEXT NOT NULL, "
            "state TEXT NOT NULL CHECK(state IN ('active','revoked')), "
            "first_seen_at INTEGER NOT NULL, revoked_at INTEGER)"
        )

    def observe(self, grant: dict, now: int, *, force_revoke: bool = False) -> str:
        """Pin a first admission; persist revoked state, never remove a tombstone."""
        digest = immutable_grant_digest(grant)
        grant_id = grant["grant_id"]
        revoke_now = bool(grant["revoked"]) or force_revoke
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute(
                "SELECT immutable_sha256, state FROM grant_pins WHERE grant_id=?",
                (grant_id,),
            ).fetchone()
            if prior and prior[0] != digest:
                raise CrossingError("grant_mutation_denied")
            if prior is None:
                state = "revoked" if revoke_now else "active"
                self.db.execute(
                    "INSERT INTO grant_pins VALUES (?, ?, ?, ?, ?)",
                    (grant_id, digest, state, now, now if revoke_now else None),
                )
            elif prior[1] == "revoked":
                state = "revoked"
            elif revoke_now:
                self.db.execute(
                    "UPDATE grant_pins SET state='revoked', revoked_at=? "
                    "WHERE grant_id=? AND state='active'",
                    (now, grant_id),
                )
                state = "revoked"
            else:
                state = "active"
            self.db.execute("COMMIT")
            return state
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self.db.close()


class MonotonicGrantGate(OperatorGrantGate):
    """R6: R5 grant validation plus monotonic local grant-ID state.

    The fixture HTTP server is deliberately single-threaded. A production
    multi-worker authorization server needs its own reviewed concurrency and
    permission model. We do not turn R4's permissive fixture into a remote API.
    """
    def __init__(self, path: str, ledger_path: str,
                 clock: Callable[[], int] | None = None):
        super().__init__(path)
        self.ledger = DurableGrantLedger(ledger_path)
        self.clock = clock or (lambda: int(time.time()))

    def __call__(self, sender: str, recipient: str, stage: str,
                 operation: str, now: int) -> None:
        grant = read_operator_grant(self.path)
        # An explicitly revoked grant MUST become a durable tombstone before
        # denial, including when no operator CLI call was used.
        if grant["revoked"]:
            try:
                self.ledger.observe(grant, self.clock(), force_revoke=True)
            except sqlite3.DatabaseError as exc:
                raise CrossingError("grant_ledger_unavailable") from exc
            raise CrossingError("grant_revoked")
        if (grant["sender"] != sender or grant["recipient"] != recipient
                or grant["stage"] != stage or operation not in grant["capabilities"]):
            raise CrossingError("grant_scope_denied")
        if not grant["not_before"] <= now < grant["expires_at"]:
            raise CrossingError("grant_expired_or_not_yet_valid")
        try:
            state = self.ledger.observe(grant, self.clock())
        except sqlite3.DatabaseError as exc:
            raise CrossingError("grant_ledger_unavailable") from exc
        if state == "revoked":
            raise CrossingError("grant_revoked")

    def close(self):
        self.ledger.close()


def revoke_fixture_grant(grant_path: str, ledger_path: str, now: int | None = None) -> dict:
    """Operator action: write irrevocable local tombstone *before* file change.

    If a JSON replacement fails, the grant is still denied by its persisted
    tombstone. Rollback of JSON alone cannot reauthorize this grant ID.
    """
    grant = read_operator_grant(grant_path)
    at = int(time.time()) if now is None else now
    ledger = DurableGrantLedger(ledger_path)
    try:
        status = ledger.observe(grant, at, force_revoke=True)
        assert status == "revoked"
    finally:
        ledger.close()
    if not grant["revoked"]:
        atomic_write_fixture_grant(grant_path, {**grant, "revoked": True})
    return {"status": "R6_FIXTURE_GRANT_REVOKED", "grant_id": grant["grant_id"],
            "local_only": True, "live_xi_connected": False}


def main():
    parser = argparse.ArgumentParser(description="R6 local TEST ONLY grant revoke command")
    parser.add_argument("revoke", choices=["revoke"])
    parser.add_argument("--grant-file", required=True)
    parser.add_argument("--ledger", required=True)
    args = parser.parse_args()
    result = revoke_fixture_grant(args.grant_file, args.ledger)
    # Grant IDs are public test identifiers, not credentials.
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
