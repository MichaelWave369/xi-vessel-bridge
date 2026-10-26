#!/usr/bin/env python3
"""R18.4: real LOCAL worker fault gauntlet using existing R16/R18.1 code.

Each case launches two separate independent R18.1 Python subprocess workers
with ephemeral pinned Ed25519 fixture keys and separate durable SQLite ledgers.
The coordinator *injects* test messages via local stdin/stdout, not a network.
NO Xi/Hunter connection, two-host results, production transport or permissions.
The redacted summary contains no key, signed message, session ID or transcript.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import phi_xi_r16_loopback as r16
import xi_pilot_r18 as r18
import xi_two_house_r181 as lab

SCHEMA = "PhiXi.R18_4_LocalWorkerFaultReport.v1"
CASE_IDS = (
    "baseline", "wrong-peer", "wrong-recipient", "signature-tamper",
    "expired", "wrong-session", "scope-escalation", "receiver-deny",
    "paused", "revoked", "duplicate", "restart-replay",
    "receipt-tamper", "lost-reply"
)
EXPECTED = {
    "baseline": "ACCEPTED",
    "wrong-peer": "REFUSED",
    "wrong-recipient": "REFUSED",
    "signature-tamper": "REFUSED",
    "expired": "REFUSED",
    "wrong-session": "REFUSED",
    "scope-escalation": "REFUSED",
    "receiver-deny": "REFUSED",
    "paused": "REFUSED",
    "revoked": "REFUSED",
    "duplicate": "REFUSED",
    "restart-replay": "REFUSED",
    "receipt-tamper": "RESULT_REFUSED",
    "lost-reply": "RETRY_REFUSED"
}
assert tuple(EXPECTED) == CASE_IDS


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def denied(worker, command, **items):
    result = worker.ask(command, expected_ok=False, **items)
    require(result == "LOCAL_FIXTURE_REFUSED", "worker did not fail closed")
    return True


def count_commits(directory):
    with sqlite3.connect(str(Path(directory) / "r181.sqlite3")) as cx:
        return cx.execute("SELECT COUNT(*) FROM requests").fetchone()[0]


def synthetic_signed(key, *, session, receiver_pin, now=None, **overrides):
    """Sign ONLY the fixed public synthetic payload; override fixed fixture fields."""
    payload = {
        "operation": lab.OPERATION, "permission_requested": "read_only",
        "dry_run": True, "input": r18.fixture()
    }
    payload.update(overrides)
    return lab.signed(key, kind="tool.request", sender="phi-sim",
                      recipient=receiver_pin, session=session,
                      request_id=str(uuid.uuid4()), payload=payload, now=now)


def case(case_id):
    require(case_id in EXPECTED, "unknown local case")
    with tempfile.TemporaryDirectory(prefix="xi-r184-local-") as tmp:
        root = Path(tmp)
        key_phi = Ed25519PrivateKey.generate()
        key_xi = Ed25519PrivateKey.generate()
        key_attacker = Ed25519PrivateKey.generate()
        path_phi, path_xi = root / "phi.key", root / "xi.key"
        r16.write_demo_private(path_phi, key_phi)
        r16.write_demo_private(path_xi, key_xi)
        session = str(uuid.uuid4())
        phi_path, xi_path = root / "phi-ledger", root / "xi-ledger"
        phi = lab.Process("phi-sim", phi_path, path_phi, r16.identity(key_xi), session)
        xi = lab.Process("xi-sim", xi_path, path_xi, r16.identity(key_phi), session)
        result = None
        confirmed = False
        replay_denied_after_restart = False
        try:
            if case_id == "receiver-deny":
                # This fixture receiver does not opt in to artifact.sha256.
                xi.command.remove("--allow-digest")
                xi.restart()
            lab.handshake(phi, xi)
            request = phi.ask("make-request")
            if case_id == "wrong-peer":
                request = synthetic_signed(key_attacker, session=session, receiver_pin=r16.identity(key_xi))
            elif case_id == "wrong-recipient":
                request = synthetic_signed(key_phi, session=session, receiver_pin=r16.identity(key_attacker))
            elif case_id == "signature-tamper":
                request = copy.deepcopy(request)
                request["payload"]["input"]["sha256"] = "0" * 64
                # Don't re-sign. Must reach genuine Ed25519 verify and be rejected.
            elif case_id == "expired":
                request = synthetic_signed(key_phi, session=session, receiver_pin=r16.identity(key_xi),
                                           now=int(time.time()) - 120)
            elif case_id == "wrong-session":
                request = synthetic_signed(key_phi, session=str(uuid.uuid4()), receiver_pin=r16.identity(key_xi))
            elif case_id == "scope-escalation":
                request = synthetic_signed(key_phi, session=session, receiver_pin=r16.identity(key_xi),
                                           operation="repo.write", permission_requested="explicit_grant")
            elif case_id == "paused":
                (xi_path / "PAUSED").touch()
            elif case_id == "revoked":
                xi.ask("revoke")

            if case_id in ("baseline", "duplicate", "restart-replay", "receipt-tamper", "lost-reply"):
                signed_result = xi.ask("accept-request", request=request)
                if case_id == "baseline":
                    receipt = phi.ask("accept-result", result=signed_result)
                    require(receipt["status"] == "LOCAL_SIGNED_SYNTHETIC_DIGEST_CONFIRMED",
                            "valid signed receipt was not confirmed")
                    confirmed = True
                    result = "ACCEPTED"
                elif case_id == "duplicate":
                    denied(xi, "accept-request", request=request)
                    phi.ask("accept-result", result=signed_result)
                    confirmed = True
                    result = "REFUSED"
                elif case_id == "restart-replay":
                    xi.restart()
                    lab.handshake(phi, xi)
                    denied(xi, "accept-request", request=request)
                    replay_denied_after_restart = True
                    result = "REFUSED"
                elif case_id == "receipt-tamper":
                    altered = copy.deepcopy(signed_result)
                    altered["payload"]["receipt"]["artifact_sha256"] = "0" * 64
                    denied(phi, "accept-result", result=altered)
                    # Original untampered signed receipt should still work.
                    good = phi.ask("accept-result", result=signed_result)
                    require(good["status"] == "LOCAL_SIGNED_SYNTHETIC_DIGEST_CONFIRMED",
                            "original receipt not subsequently accepted")
                    confirmed = True
                    result = "RESULT_REFUSED"
                else:
                    # Coordinator drops result after receiver durable COMMIT.
                    # Requester never receives it. A retry must not execute twice.
                    denied(xi, "accept-request", request=request)
                    result = "RETRY_REFUSED"
            else:
                denied(xi, "accept-request", request=request)
                result = "REFUSED"
                if case_id == "revoked":
                    xi.restart()
                    denied(xi, "challenge")
            require(result == EXPECTED[case_id], "unexpected cryptographic fixture outcome")
            count = count_commits(xi_path)
            expected_commits = 1 if case_id in (
                "baseline", "duplicate", "restart-replay", "receipt-tamper", "lost-reply"
            ) else 0
            require(count == expected_commits,
                    "receiver durable ledger count does not match expected at-most-once behavior")
            return {
                "scenario_id": case_id, "expected": EXPECTED[case_id],
                "observed": result, "pass": True, "receiver_commits": count,
                "requester_confirmed": confirmed, "replay_refused_after_restart": replay_denied_after_restart,
                "local_worker_processes": 2, "physical_hosts": 1,
                "real_ed25519_fixture": True, "network_transport": False,
                "live_xi_connected": False, "authority": "none"
            }
        finally:
            try:
                phi.stop()
            finally:
                xi.stop()


def report(cases=CASE_IDS):
    cases = tuple(cases)
    require(cases == CASE_IDS, "redacted report must include the entire exact R18.3 case roster")
    outcome = [case(case_id) for case_id in cases]
    require(all(row["pass"] is True and row["live_xi_connected"] is False
                for row in outcome), "local worker gauntlet failed")
    return {
        "schema": SCHEMA,
        "classification": "LOCAL_TWO_PROCESS_CRYPTOGRAPHIC_FIXTURE_ONLY",
        "status": "LOCAL_R18_4_GAUNTLET_PASS",
        "case_count": len(CASE_IDS), "passed_count": len(outcome),
        "cases": outcome,
        "physical_hosts": 1, "distinct_worker_processes_per_case": 2,
        "real_ed25519_fixture": True, "actual_xi_peer_authenticated": False,
        "remote_transport": False, "independent_xi_receipts": 0,
        "external_gates_promoted": 0,
        "r17_external_pilot": "BLOCKED", "r18_real_two_host_pilot": "NOT_RUN",
        "live_xi_connected": False, "authority": "none",
        "qualification": "Executed signed local Python worker fixtures. Not a real Xi peer, network pilot, operator grant or independent security audit."
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("demo", "require-live"))
    args = p.parse_args(argv)
    if args.action == "require-live":
        print("R18_4_REFUSED: LOCAL fixtures cannot promote real Xi authority", file=sys.stderr)
        return 2
    try:
        print(json.dumps(report(), sort_keys=True, indent=2))
        return 0
    except (RuntimeError, lab.Refused, r16.Refused, OSError, ValueError, sqlite3.Error):
        print(json.dumps({"status": "R18_4_LOCAL_GAUNTLET_REFUSED",
                          "live_xi_connected": False, "authority": "none"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
