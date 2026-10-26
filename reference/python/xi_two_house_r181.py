#!/usr/bin/env python3
"""R18.1: two independently keyed *local processes* simulate two sovereign houses.

R16 proves pinned ephemeral Ed25519 key possession on both sides. R18 supplies
the exact synthetic payload. Signed xi.exchange.v1-shaped envelopes exercise
digest-only tool.request/tool.result and durable idempotency. This fixture
cryptographic profile is NOT an approved native Xi wire contract, authentic
Hunter identity, independent consent, encrypted transport, or two-host pilot.
No sockets, browser, server bind, external files, credentials or remote tools.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

import phi_xi_r16_loopback as r16
import xi_pilot_r18 as r18

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "xi.exchange.v1"
SUITE = "PhiXi.R18_1_LocalEd25519Fixture.v1"
ROOM = "r181_simulated_only"
OPERATION = "artifact.sha256"
TTL = 45
MAX_LINE = 12 * 1024
ROLES = {"phi-sim", "xi-sim"}
ENVELOPE = {"protocol", "message_id", "request_id", "session_id", "sender",
            "recipient", "type", "created_at", "expires_at", "payload", "auth", "signature"}
INPUT = {"operation", "permission_requested", "input", "dry_run"}
RESULT = {"operation", "request_sha256", "receipt"}
RECEIPT = {"request_id", "operation", "status", "receiver", "recorded_at",
           "execution_count", "artifact_sha256"}
AUTH = {"suite", "room", "public_key"}


class Refused(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def utc(now):
    return datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def epoch(text):
    require(isinstance(text, str) and len(text) == 20 and text.endswith("Z"),
            "invalid timestamp")
    try:
        return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except ValueError as exc:
        raise Refused("invalid timestamp") from exc


def uid(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value,
            "invalid canonical UUID")
    return value


def clean_name(value):
    require(isinstance(value, str) and value in ROLES, "unrecognized local role")
    return value


def signed(key, *, kind, sender, recipient, session, request_id, payload, now=None):
    now = int(time.time()) if now is None else int(now)
    me, peer = r16.identity(key), r16.check_identity(recipient)
    envelope = {
        "protocol": SCHEMA, "message_id": str(uuid.uuid4()),
        "request_id": uid(request_id), "session_id": uid(session),
        "sender": {"system": clean_name(sender), "instance": me},
        "recipient": {"system": clean_name("xi-sim" if sender == "phi-sim" else "phi-sim"),
                      "instance": peer},
        "type": kind, "created_at": utc(now), "expires_at": utc(now + TTL),
        "payload": payload, "auth": {"suite": SUITE, "room": ROOM, "public_key": me}
    }
    require(kind in ("tool.request", "tool.result"), "unexpected envelope type")
    envelope["signature"] = base64.b64encode(key.sign(r16.canonical(envelope))).decode("ascii")
    require(len(r16.canonical(envelope)) < MAX_LINE, "oversized signed message")
    return envelope


def verify_envelope(doc, *, kind, expected_role, expected_pin, own_role, own_pin, session, now=None):
    now = int(time.time()) if now is None else int(now)
    require(isinstance(doc, dict) and set(doc) == ENVELOPE, "unexpected envelope keys")
    require(doc["protocol"] == SCHEMA and doc["type"] == kind,
            "wrong exchange grammar")
    require(doc["session_id"] == uid(session), "unmatched session")
    uid(doc["message_id"])
    uid(doc["request_id"])
    require(doc["sender"] == {"system": expected_role, "instance": expected_pin} and
            doc["recipient"] == {"system": own_role, "instance": own_pin},
            "role/identity or recipient pin mismatch")
    require(doc["auth"] == {"suite": SUITE, "room": ROOM, "public_key": expected_pin},
            "foreign auth suite or room")
    first, last = epoch(doc["created_at"]), epoch(doc["expires_at"])
    require(last - first == TTL and first <= now + 10 and now <= last and
            abs(first - now) <= TTL, "message timestamp or expiry refused")
    require(isinstance(doc["payload"], dict), "payload must be JSON object")
    try:
        raw_sig = r16.b64decode(doc["signature"])
        require(len(raw_sig) == 64, "invalid signature length")
        Ed25519PublicKey.from_public_bytes(
            r16.b64decode(expected_pin[len(r16.KEY_PREFIX):])
        ).verify(raw_sig, r16.canonical({k: v for k, v in doc.items() if k != "signature"}))
    except Exception as exc:
        raise Refused("unverified signed envelope") from exc
    return doc


class House:
    """Each instance owns key, independent room gate, allowlist and SQLite ledger."""

    def __init__(self, state, key, peer_pin, role, session, *, allow_digest=False):
        self.state = Path(state)
        require(not self.state.is_symlink(), "state must not be symlink")
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key = key
        self.me = r16.identity(key)
        self.peer_pin = r16.check_identity(peer_pin)
        self.role = clean_name(role)
        self.peer_role = clean_name("xi-sim" if role == "phi-sim" else "phi-sim")
        self.session = uid(session)
        self.allowed_operations = {OPERATION} if allow_digest else set()
        self.gate = r16.Gate(self.state, key, peer_pin, ROOM)
        self.db = self.state / "r181.sqlite3"
        require(not self.db.is_symlink(), "ledger must not be symlink")
        with self.connect() as cx:
            cx.execute("CREATE TABLE IF NOT EXISTS requests (request_id TEXT PRIMARY KEY,"
                       " sender TEXT NOT NULL, request_sha TEXT NOT NULL,"
                       " result_sha TEXT NOT NULL, processed_at INTEGER NOT NULL)")
            cx.execute("CREATE TABLE IF NOT EXISTS outgoing (request_id TEXT PRIMARY KEY,"
                       " request_sha TEXT NOT NULL, confirmed INTEGER NOT NULL DEFAULT 0)")
        self.inbound_ready = False
        self.outbound_ready = False
        self.outgoing_proofs = {}

    def connect(self):
        cx = sqlite3.connect(self.db, timeout=5)
        cx.execute("PRAGMA busy_timeout=5000")
        return cx

    def permit(self):
        with self.gate.connect() as cx:
            self.gate.permitted(cx)

    def ready(self):
        self.permit()
        require(self.inbound_ready and self.outbound_ready,
                "local bilateral handshake not completed")

    def challenge(self, now=None):
        return self.gate.challenge(self.peer_pin, now=now)

    def proof(self, challenge, now=None):
        proof = r16.make_proof(challenge, self.key, self.peer_pin, ROOM, now=now)
        self.outgoing_proofs[proof["id"]] = proof
        return proof

    def accept_proof(self, proof, now=None):
        receipt = self.gate.prove(proof, now=now)
        self.inbound_ready = True
        return receipt

    def confirm(self, receipt, now=None):
        proof = self.outgoing_proofs.get(receipt.get("id") if isinstance(receipt, dict) else None)
        require(proof is not None, "unknown outgoing handshake proof")
        r16.verify_receipt(receipt, proof, self.peer_pin, ROOM, now=now)
        self.outbound_ready = True
        self.outgoing_proofs.pop(proof["id"])
        return {"local_handshake": "PINNED_FIXTURE_ONLY", "authority": "none"}

    def make_request(self, now=None):
        self.ready()
        doc = signed(self.key, kind="tool.request", sender=self.role, recipient=self.peer_pin,
                     session=self.session, request_id=str(uuid.uuid4()),
                     payload={"operation": OPERATION, "permission_requested": "read_only",
                              "input": r18.fixture(), "dry_run": True}, now=now)
        with self.connect() as cx:
            cx.execute("INSERT INTO outgoing(request_id,request_sha) VALUES (?,?)",
                       (doc["request_id"], r16.sha256(r16.canonical(doc))))
        return doc

    def accept_request(self, doc, now=None):
        self.ready()
        now = int(time.time()) if now is None else int(now)
        verify_envelope(doc, kind="tool.request", expected_role=self.peer_role,
                        expected_pin=self.peer_pin, own_role=self.role,
                        own_pin=self.me, session=self.session, now=now)
        p = doc["payload"]
        require(set(p) == INPUT and p["operation"] == OPERATION and
                p["permission_requested"] == "read_only" and p["dry_run"] is True,
                "operation scope or permission not allowed")
        require(OPERATION in self.allowed_operations,
                "receiving house did not permit digest operation")
        r18.verify_fixture(p["input"])
        request_hash = r16.sha256(r16.canonical(doc))
        receipt = {
            "request_id": doc["request_id"], "operation": OPERATION, "status": "completed",
            "receiver": self.role, "recorded_at": utc(now), "execution_count": 1,
            "artifact_sha256": r18.sha(r18.PAYLOAD)
        }
        output = signed(self.key, kind="tool.result", sender=self.role,
                        recipient=self.peer_pin, session=self.session,
                        request_id=doc["request_id"],
                        payload={"operation": OPERATION, "request_sha256": request_hash,
                                 "receipt": receipt}, now=now)
        # Commit before returning a signed receipt. If interrupted after commit,
        # fail closed: never execute a duplicate accepted request ID.
        with self.connect() as cx:
            cx.execute("BEGIN IMMEDIATE")
            try:
                cx.execute("INSERT INTO requests(request_id,sender,request_sha,result_sha,processed_at)"
                           " VALUES (?,?,?,?,?)",
                           (doc["request_id"], self.peer_pin, request_hash,
                            r16.sha256(r16.canonical(output)), now))
                self.permit()
                cx.commit()
            except Exception:
                cx.rollback()
                raise
        return output

    def accept_result(self, result, now=None):
        self.ready()
        now = int(time.time()) if now is None else int(now)
        verify_envelope(result, kind="tool.result", expected_role=self.peer_role,
                        expected_pin=self.peer_pin, own_role=self.role,
                        own_pin=self.me, session=self.session, now=now)
        p = result["payload"]
        require(set(p) == RESULT and p["operation"] == OPERATION and
                isinstance(p["receipt"], dict) and set(p["receipt"]) == RECEIPT,
                "result or receipt fields mismatch")
        receipt = p["receipt"]
        require(receipt["request_id"] == result["request_id"] and
                receipt["operation"] == OPERATION and receipt["status"] == "completed" and
                receipt["receiver"] == self.peer_role and
                type(receipt["execution_count"]) is int and receipt["execution_count"] == 1 and
                receipt["artifact_sha256"] == r18.sha(r18.PAYLOAD) and
                receipt["recorded_at"] == result["created_at"],
                "result receipt mismatch")
        with self.connect() as cx:
            cx.execute("BEGIN IMMEDIATE")
            row = cx.execute("SELECT request_sha,confirmed FROM outgoing WHERE request_id=?",
                             (result["request_id"],)).fetchone()
            require(row is not None and row[0] == p["request_sha256"] and not row[1],
                    "unknown, tampered or replayed result")
            cx.execute("UPDATE outgoing SET confirmed=1 WHERE request_id=?",
                       (result["request_id"],))
            cx.commit()
        return {"status": "LOCAL_SIGNED_SYNTHETIC_DIGEST_CONFIRMED",
                "operation": OPERATION, "receipt_sha256": r16.sha256(r16.canonical(result)),
                "authority": "none", "live_xi_connected": False}

    def revoke(self):
        self.gate.revoke()
        self.inbound_ready = False
        self.outbound_ready = False
        return {"revoked_locally": True, "remote_access_created": False}


def handle(house, item):
    require(isinstance(item, dict) and "command" in item, "missing fixture command")
    action = item["command"]
    args = set(item)
    allowed = {
        "challenge": {"command"}, "proof": {"command", "challenge"},
        "accept-proof": {"command", "proof"}, "confirm": {"command", "receipt"},
        "make-request": {"command"}, "accept-request": {"command", "request"},
        "accept-result": {"command", "result"}, "revoke": {"command"}
    }
    require(action in allowed and args == allowed[action], "unknown local fixture RPC")
    if action == "challenge":
        return house.challenge()
    if action == "proof":
        return house.proof(item["challenge"])
    if action == "accept-proof":
        return house.accept_proof(item["proof"])
    if action == "confirm":
        return house.confirm(item["receipt"])
    if action == "make-request":
        return house.make_request()
    if action == "accept-request":
        return house.accept_request(item["request"])
    if action == "accept-result":
        return house.accept_result(item["result"])
    return house.revoke()


def worker(args):
    key = r16.load_private(args.key)
    house = House(args.state, key, args.peer_pin, args.role, args.session,
                  allow_digest=args.allow_digest)
    for raw in sys.stdin.buffer:
        try:
            require(len(raw) <= MAX_LINE, "oversized worker command")
            item = json.loads(raw.decode("utf-8"))
            result = {"ok": True, "result": handle(house, item)}
        except (Refused, r16.Refused, r18.Refused, ValueError, KeyError, TypeError,
                UnicodeError, sqlite3.Error):
            # Do not echo untrusted contents, identities, paths or key material.
            result = {"ok": False, "error": "LOCAL_FIXTURE_REFUSED"}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


class Process:
    def __init__(self, role, state, key_path, peer_pin, session):
        self.command = [
            sys.executable, str(Path(__file__).resolve()), "worker",
            "--state", str(state), "--key", str(key_path), "--peer-pin", peer_pin,
            "--role", role, "--session", session, "--allow-digest"
        ]
        self.proc = None
        self.start()

    def start(self):
        self.proc = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     bufsize=0)

    def ask(self, action, *, expected_ok=True, **items):
        require(self.proc.poll() is None, "simulated house process terminated")
        raw = r16.canonical({"command": action, **items}) + b"\n"
        require(len(raw) < MAX_LINE, "oversized coordinator request")
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()
        response = self.proc.stdout.readline(MAX_LINE + 1)
        require(0 < len(response) <= MAX_LINE, "missing or oversized process response")
        obj = json.loads(response)
        require(isinstance(obj, dict) and obj.get("ok") is expected_ok,
                "unexpected house response or missing refusal")
        return obj.get("result") if expected_ok else obj.get("error")

    def stop(self):
        if self.proc is not None:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
            self.proc.stdout.close()

    def restart(self):
        self.stop()
        self.start()


def handshake(phi, xi):
    for server, client in ((phi, xi), (xi, phi)):
        challenge = server.ask("challenge")
        proof = client.ask("proof", challenge=challenge)
        receipt = server.ask("accept-proof", proof=proof)
        client.ask("confirm", receipt=receipt)


def demo():
    with tempfile.TemporaryDirectory(prefix="phi-xi-r181-") as tmp:
        root = Path(tmp)
        phi_key, xi_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        phi_path, xi_path = root / "phi.key", root / "xi.key"
        r16.write_demo_private(phi_path, phi_key)
        r16.write_demo_private(xi_path, xi_key)
        session = str(uuid.uuid4())
        phi = Process("phi-sim", root / "phi-state", phi_path, r16.identity(xi_key), session)
        xi = Process("xi-sim", root / "xi-state", xi_path, r16.identity(phi_key), session)
        try:
            handshake(phi, xi)
            # Both independent houses have opted in to digest-only, local policy.
            request = phi.ask("make-request")
            result = xi.ask("accept-request", request=request)
            confirmed = phi.ask("accept-result", result=result)
            require(confirmed["status"] == "LOCAL_SIGNED_SYNTHETIC_DIGEST_CONFIRMED",
                    "signed read-only round trip failed")
            xi.ask("accept-request", expected_ok=False, request=request)
            phi.ask("accept-result", expected_ok=False, result=result)
            # Interchange direction; a second peer does not inherit PHI's ledger.
            backward = xi.ask("make-request")
            back_receipt = phi.ask("accept-request", request=backward)
            xi.ask("accept-result", result=back_receipt)
            # Crash/restart Xi; redo mutual handshake, then old request still refused.
            xi.restart()
            handshake(phi, xi)
            xi.ask("accept-request", expected_ok=False, request=request)
            mutated = dict(phi.ask("make-request"))
            mutated["payload"] = dict(mutated["payload"])
            mutated["payload"]["operation"] = "repo.write"
            xi.ask("accept-request", expected_ok=False, request=mutated)
            (root / "xi-state" / "PAUSED").touch()
            paused_request = phi.ask("make-request")
            xi.ask("accept-request", expected_ok=False, request=paused_request)
            (root / "xi-state" / "PAUSED").unlink()
            xi.ask("revoke")
            xi.ask("accept-request", expected_ok=False, request=paused_request)
            xi.restart()
            xi.ask("challenge", expected_ok=False)
        finally:
            phi.stop()
            xi.stop()
    return {
        "status": "R18_1_TWO_HOUSE_LOCAL_SIMULATION_PASS",
        "process_count": 2, "distinct_ephemeral_identity_keys": True,
        "bilateral_r16_handshake": True,
        "signed_xi_exchange_v1_shaped_digest_roundtrip": True,
        "bidirectional_local_digest": True,
        "durable_request_replay_refused_after_restart": True,
        "receiver_pause_refused": True,
        "receiver_revocation_survived_restart": True,
        "source_fixture_sha256": r18.sha(r18.PAYLOAD),
        "permitted_operation": OPERATION, "cross_host_network": False,
        "physical_hosts": 1, "real_xi_peer_verified": False,
        "two_physical_hosts_confirmed": False, "live_xi_connected": False,
        "r17_external_pilot": "BLOCKED", "r18_real_two_host_pilot": "NOT_RUN",
        "authority": "none",
        "qualification": "Two local synthetic processes, fixture-only cryptography and permissions."
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("demo")
    sub.add_parser("require-live")
    wk = sub.add_parser("worker")
    wk.add_argument("--state", type=Path, required=True)
    wk.add_argument("--key", type=Path, required=True)
    wk.add_argument("--peer-pin", required=True)
    wk.add_argument("--role", choices=tuple(sorted(ROLES)), required=True)
    wk.add_argument("--session", required=True)
    wk.add_argument("--allow-digest", action="store_true", default=False)
    args = p.parse_args(argv)
    if args.action == "require-live":
        print("R18_1_REFUSED: local dual-process simulation is not a live Xi crossing",
              file=sys.stderr)
        return 2
    try:
        if args.action == "worker":
            return worker(args)
        print(json.dumps(demo(), indent=2, sort_keys=True))
        return 0
    except (Refused, r16.Refused, r18.Refused, OSError, ValueError, sqlite3.Error):
        print(json.dumps({"status": "R18_1_LOCAL_SIMULATION_REFUSED",
                          "live_xi_connected": False, "authority": "none"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
