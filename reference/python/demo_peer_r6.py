#!/usr/bin/env python3
"""R6: local two-process grant rollback and restart negative-control demo."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from demo_peer_r4 import fixture_profiles, start_fixture_server
from xi_peer_r3 import make_offer, seal
from xi_peer_r4_http import PATH, exchange, post_loopback, read_fixture_profile
from xi_peer_r5_policy import atomic_write_fixture_grant, fixture_grant

HERE = Path(__file__).resolve().parent
STAGE = "r6-durable-fixture-stage"


def stop(process):
    process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def expect_refused(phi, url, offer, reason):
    frame = seal(offer, sender=phi.local_id, recipient=phi.peer_id, stage=STAGE,
                 sender_keys=phi.keys, recipient_public=phi.peer)
    status, result = post_loopback(url, frame)
    if (status, result.get("reason")) != (403, reason):
        raise RuntimeError("R6 refusal control did not match expected reason")


def main():
    with tempfile.TemporaryDirectory(prefix="xi-phi-r6-") as root:
        directory = Path(root)
        phi_file, xi_file = fixture_profiles(directory)
        phi = read_fixture_profile(str(phi_file))
        grant_file = directory / "operator-grant.json"
        ledger_file = directory / "operator-grants.sqlite3"
        now = int(time.time())
        grant = fixture_grant(sender=phi.local_id, recipient=phi.peer_id, stage=STAGE,
                              not_before=now-10, expires_at=now+120)
        atomic_write_fixture_grant(str(grant_file), grant)
        offer = make_offer("⟨ Ξ ⋈ Φ ⟩", {"kind": "synthetic-demo"},
                           {"author": phi.local_id, "source": "r6-fixture",
                            "version": "r6", "intended_use": "rollback and restart test"})
        proc, port = start_fixture_server(xi_file, directory, stage=STAGE,
                                          grant_file=grant_file, grant_ledger=ledger_file)
        url = f"http://127.0.0.1:{port}{PATH}"
        try:
            accepted = exchange(phi, STAGE, url, offer)
            if not accepted["receipt_matches_offer"]:
                raise RuntimeError("initial receipt invalid")
            # A mutation to the same grant ID cannot increase its authority
            # or extend its lifetime without a new operator decision.
            changed = dict(grant)
            changed["expires_at"] += 1
            atomic_write_fixture_grant(str(grant_file), changed)
            expect_refused(phi, url, offer, "grant_mutation_denied")
            atomic_write_fixture_grant(str(grant_file), grant)
            accepted = exchange(phi, STAGE, url, offer)
            if not accepted["receipt_matches_offer"]:
                raise RuntimeError("original grant should still work")
            # Distinct operator CLI process persists the irreversible tombstone.
            revoked = subprocess.run(
                [sys.executable, str(HERE / "xi_peer_r6_ledger.py"), "revoke",
                 "--grant-file", str(grant_file), "--ledger", str(ledger_file)],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=10)
            if revoked.returncode != 0:
                raise RuntimeError("offline operator revoke command failed")
            if json.loads(revoked.stdout).get("status") != "R6_FIXTURE_GRANT_REVOKED":
                raise RuntimeError("unexpected revoke receipt")
            # Replay old JSON: ledger must still refuse the same grant ID.
            atomic_write_fixture_grant(str(grant_file), grant)
            expect_refused(phi, url, offer, "grant_revoked")
        finally:
            stop(proc)
        # Restart the receiver process, reusing the same durable grant ledger.
        proc, port = start_fixture_server(xi_file, directory, stage=STAGE,
                                          grant_file=grant_file, grant_ledger=ledger_file)
        try:
            url = f"http://127.0.0.1:{port}{PATH}"
            expect_refused(phi, url, offer, "grant_revoked")
            print(json.dumps({
                "status": "R6_MONOTONIC_REVOCATION_VERIFIED",
                "cryptographic_receipt_verified": True,
                "same_id_mutation_denied": True,
                "operator_revoke_persisted": True,
                "old_grant_file_rollback_denied": True,
                "server_restart_keeps_revocation": True,
                "live_xi_connected": False,
            }, indent=2))
        finally:
            stop(proc)


if __name__ == "__main__":
    main()
