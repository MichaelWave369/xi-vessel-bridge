#!/usr/bin/env python3
"""R16: two-process, loopback-only, mutually pinned Phi-Xi handshake fixture.

No Xi endpoint, filesystem serving, relay deliveries, remote tools or grants.
A pinned Ed25519 key authenticates a test identity only, NOT a human or Xi seat.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "PhiXi.Handshake.R16.fixture.v1"
SCOPE = "handshake.observe"
TTL = 45
MAX_BODY = 4096
KEY_PREFIX = "ed25519:"
FIELDS = {
    "challenge": {"schema", "kind", "id", "from", "to", "room", "scope", "nonce", "ts", "expires", "sig"},
    "prove": {"schema", "kind", "id", "from", "to", "room", "scope", "nonce", "client_nonce", "ts", "sig"},
    "receipt": {"schema", "kind", "id", "from", "to", "room", "scope", "client_nonce", "proof_sha256", "ts", "status", "sig"},
}


class Refused(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def b64decode(value):
    if not isinstance(value, str):
        raise Refused("invalid base64")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refused("invalid base64") from exc


def identity(key):
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return KEY_PREFIX + base64.b64encode(public).decode("ascii")


def check_identity(value):
    if not isinstance(value, str) or not value.startswith(KEY_PREFIX):
        raise Refused("invalid peer identity")
    if len(b64decode(value[len(KEY_PREFIX):])) != 32:
        raise Refused("invalid public key length")
    return value


def sign(key, kind, **fields):
    if kind not in FIELDS:
        raise Refused("unsupported message kind")
    msg = {"schema": SCHEMA, "kind": kind, "from": identity(key), **fields}
    if set(msg) != FIELDS[kind] - {"sig"}:
        raise Refused("signed message fields mismatch")
    msg["sig"] = base64.b64encode(key.sign(canonical(msg))).decode("ascii")
    return msg


def verify(msg, kind, expected_peer):
    if not isinstance(msg, dict) or set(msg) != FIELDS[kind]:
        raise Refused("invalid message fields")
    if msg["schema"] != SCHEMA or msg["kind"] != kind or msg["scope"] != SCOPE:
        raise Refused("unexpected schema, kind or scope")
    if msg["from"] != expected_peer or not isinstance(msg["id"], str):
        raise Refused("peer identity or id mismatch")
    check_identity(expected_peer)
    signature = b64decode(msg["sig"])
    if len(signature) != 64:
        raise Refused("invalid signature length")
    try:
        Ed25519PublicKey.from_public_bytes(b64decode(expected_peer[len(KEY_PREFIX):])).verify(
            signature, canonical({key: value for key, value in msg.items() if key != "sig"}))
    except Exception as exc:
        raise Refused("signature invalid") from exc


def valid_room(room):
    if not isinstance(room, str) or not (1 <= len(room) <= 60) or any(
        c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in room
    ):
        raise Refused("room must be a short explicit safe identifier")
    return room


def load_private(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Refused("private key must be a regular local file")
    if os.name == "posix" and (path.stat().st_mode & 0o077):
        raise Refused("private key must not be readable by group/other")
    raw = path.read_bytes()
    if len(raw) != 32:
        raise Refused("expected raw 32-byte Ed25519 private key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def write_demo_private(path, key):
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)


class Gate:
    """Durable challenge/consumption/revocation ledger; fixture-only authorization."""

    def __init__(self, state, server_key, pinned_client, room):
        self.state = Path(state)
        if self.state.is_symlink():
            raise Refused("state directory cannot be a symlink")
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key = server_key
        self.pinned = check_identity(pinned_client)
        self.room = valid_room(room)
        self.db = self.state / "r16.sqlite3"
        if self.db.is_symlink():
            raise Refused("ledger cannot be a symlink")
        with self.connect() as cx:
            cx.execute("CREATE TABLE IF NOT EXISTS issued (id TEXT PRIMARY KEY, nonce TEXT NOT NULL, peer TEXT NOT NULL, room TEXT NOT NULL, expires INTEGER NOT NULL, spent INTEGER NOT NULL DEFAULT 0)")
            cx.execute("CREATE TABLE IF NOT EXISTS revoked (peer TEXT PRIMARY KEY, ts INTEGER NOT NULL)")

    def connect(self):
        cx = sqlite3.connect(self.db, timeout=5, isolation_level=None)
        cx.execute("PRAGMA busy_timeout=5000")
        return cx

    def permitted(self, cx):
        if (self.state / "PAUSED").exists():
            raise Refused("locally paused")
        if cx.execute("SELECT 1 FROM revoked WHERE peer=?", (self.pinned,)).fetchone():
            raise Refused("peer locally revoked")

    def challenge(self, peer, now=None):
        if peer != self.pinned:
            raise Refused("unapproved fixture peer")
        now = int(time.time()) if now is None else int(now)
        token_id = secrets.token_hex(16)
        nonce = secrets.token_urlsafe(24)
        with self.connect() as cx:
            cx.execute("BEGIN IMMEDIATE")
            self.permitted(cx)
            cx.execute("INSERT INTO issued(id, nonce, peer, room, expires) VALUES (?,?,?,?,?)",
                       (token_id, nonce, peer, self.room, now + TTL))
            cx.commit()
        return sign(self.key, "challenge", id=token_id, to=peer, room=self.room,
                    scope=SCOPE, nonce=nonce, ts=now, expires=now + TTL)

    def prove(self, proof, now=None):
        now = int(time.time()) if now is None else int(now)
        verify(proof, "prove", self.pinned)
        if (proof["to"] != identity(self.key) or proof["room"] != self.room or
                not isinstance(proof["client_nonce"], str) or len(proof["client_nonce"]) < 16 or
                type(proof["ts"]) is not int or abs(proof["ts"] - now) > TTL):
            raise Refused("proof binding or freshness invalid")
        with self.connect() as cx:
            cx.execute("BEGIN IMMEDIATE")
            self.permitted(cx)
            row = cx.execute("SELECT nonce,peer,room,expires,spent FROM issued WHERE id=?",
                             (proof["id"],)).fetchone()
            if row is None:
                raise Refused("unknown challenge")
            nonce, peer, room, expiry, spent = row
            if spent:
                raise Refused("durable replay refusal")
            if now > expiry or proof["ts"] > expiry:
                raise Refused("challenge expired")
            if proof["nonce"] != nonce or peer != self.pinned or room != self.room:
                raise Refused("challenge binding mismatch")
            result = cx.execute("UPDATE issued SET spent=1 WHERE id=? AND spent=0", (proof["id"],))
            if result.rowcount != 1:
                raise Refused("concurrent replay")
            cx.commit()
        return sign(self.key, "receipt", id=proof["id"], to=self.pinned, room=self.room,
                    scope=SCOPE, client_nonce=proof["client_nonce"],
                    proof_sha256=sha256(canonical(proof)), ts=now, status="fixture-accepted")

    def revoke(self):
        with self.connect() as cx:
            cx.execute("BEGIN IMMEDIATE")
            cx.execute("INSERT OR REPLACE INTO revoked(peer,ts) VALUES (?,?)",
                       (self.pinned, int(time.time())))
            cx.commit()


def make_proof(challenge, client_key, pinned_server, room, now=None):
    verify(challenge, "challenge", pinned_server)
    now = int(time.time()) if now is None else int(now)
    if (challenge["to"] != identity(client_key) or challenge["room"] != valid_room(room)
            or type(challenge["ts"]) is not int or type(challenge["expires"]) is not int
            or challenge["ts"] > now + 10 or now > challenge["expires"]
            or challenge["expires"] - challenge["ts"] != TTL
            or not isinstance(challenge["nonce"], str) or len(challenge["nonce"]) < 16):
        raise Refused("server challenge has wrong target, room or time")
    return sign(client_key, "prove", id=challenge["id"], to=pinned_server, room=room,
                scope=SCOPE, nonce=challenge["nonce"], client_nonce=secrets.token_urlsafe(24),
                ts=now)


def verify_receipt(receipt, proof, pinned_server, room, now=None):
    verify(receipt, "receipt", pinned_server)
    now = int(time.time()) if now is None else int(now)
    if (receipt["id"] != proof["id"] or receipt["to"] != proof["from"] or
            receipt["room"] != valid_room(room) or receipt["client_nonce"] != proof["client_nonce"] or
            receipt["proof_sha256"] != sha256(canonical(proof)) or
            receipt["status"] != "fixture-accepted" or type(receipt["ts"]) is not int or
            abs(receipt["ts"] - now) > TTL):
        raise Refused("server receipt binding invalid")


def post_json(port, route, payload):
    data = canonical(payload)
    req = Request("http://127.0.0.1:" + str(port) + route, data=data,
                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=3) as resp:
            return resp.status, json.loads(resp.read(MAX_BODY + 1))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read(MAX_BODY + 1))


def serve(args):
    if args.host != "127.0.0.1":
        raise Refused("R16 refuses all non-loopback binds")
    gate = Gate(args.state, load_private(args.key), args.peer, args.room)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *values):
            # No untrusted payloads, peer IDs, or private local paths in logs.
            pass

        def do_POST(self):
            try:
                if self.path not in ("/r16/challenge", "/r16/prove"):
                    raise Refused("unknown route")
                length = self.headers.get("Content-Length")
                if length is None or not length.isdecimal() or int(length) > MAX_BODY:
                    raise Refused("missing or oversized content")
                data = self.rfile.read(int(length))
                payload = json.loads(data)
                if self.path == "/r16/challenge":
                    if not isinstance(payload, dict) or set(payload) != {"peer"}:
                        raise Refused("challenge input must name one peer")
                    answer = gate.challenge(payload["peer"])
                else:
                    answer = gate.prove(payload)
                status = 200
            except (Refused, ValueError, KeyError, TypeError, json.JSONDecodeError):
                status = 403
                answer = {"status": "refused", "live_xi_connected": False}
            body = canonical(answer)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class LoopbackServer(ThreadingHTTPServer):
        daemon_threads = True

    with LoopbackServer(("127.0.0.1", args.port), Handler) as server:
        server.serve_forever()


def client(args):
    key = load_private(args.key)
    pinned_server = check_identity(args.server_pin)
    code, challenge = post_json(args.port, "/r16/challenge", {"peer": identity(key)})
    if code != 200:
        raise Refused("server refused challenge")
    proof = make_proof(challenge, key, pinned_server, args.room)
    code, receipt = post_json(args.port, "/r16/prove", proof)
    if code != 200:
        raise Refused("server refused proof")
    verify_receipt(receipt, proof, pinned_server, args.room)
    return {"status": "mutually_authenticated_local_fixture", "scope": SCOPE,
            "receipt_sha256": sha256(canonical(receipt)), "durable_server_replay_gate": True,
            "live_xi_connected": False, "transport": "loopback-http-only"}


def demo():
    with tempfile.TemporaryDirectory(prefix="phi-xi-r16-") as tmp:
        root = Path(tmp)
        server_key = Ed25519PrivateKey.generate()
        client_key = Ed25519PrivateKey.generate()
        server_path, client_path = root / "server.key", root / "client.key"
        write_demo_private(server_path, server_key)
        write_demo_private(client_path, client_key)
        state = root / "state"
        room = "r16_fixture"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]

        command = [sys.executable, str(Path(__file__).resolve()), "serve",
                   "--host", "127.0.0.1", "--port", str(port), "--state", str(state),
                   "--key", str(server_path), "--peer", identity(client_key), "--room", room]
        def start():
            proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            for _ in range(100):
                if proc.poll() is not None:
                    raise Refused("fixture server failed to start")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        return proc
                except OSError:
                    time.sleep(.05)
            proc.terminate()
            proc.wait(timeout=3)
            raise Refused("fixture server start timeout")

        def stop(proc):
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            proc.stderr.close()

        proc = start()
        try:
            status, challenge = post_json(port, "/r16/challenge", {"peer": identity(client_key)})
            if status != 200:
                raise Refused("challenge failed")
            proof = make_proof(challenge, client_key, identity(server_key), room)
            status, receipt = post_json(port, "/r16/prove", proof)
            if status != 200:
                raise Refused("proof failed")
            verify_receipt(receipt, proof, identity(server_key), room)
            status, _ = post_json(port, "/r16/prove", proof)
            if status == 200:
                raise Refused("replay was accepted")
        finally:
            stop(proc)

        proc = start()
        try:
            status, _ = post_json(port, "/r16/prove", proof)
            if status == 200:
                raise Refused("replay survived restart")
            (state / "PAUSED").touch()
            status, _ = post_json(port, "/r16/challenge", {"peer": identity(client_key)})
            if status == 200:
                raise Refused("paused challenge accepted")
            (state / "PAUSED").unlink()
            Gate(state, server_key, identity(client_key), room).revoke()
            status, _ = post_json(port, "/r16/challenge", {"peer": identity(client_key)})
            if status == 200:
                raise Refused("revoked peer accepted")
        finally:
            stop(proc)
    return {"status": "R16_LOCAL_FIXTURE_PASS", "separate_processes": True,
            "mutually_signed": True, "replay_refused_after_restart": True,
            "pause_refused": True, "revocation_refused": True,
            "live_xi_connected": False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest="action", required=True)
    subs.add_parser("demo")
    serve_cmd = subs.add_parser("serve")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, required=True)
    serve_cmd.add_argument("--state", type=Path, required=True)
    serve_cmd.add_argument("--key", type=Path, required=True)
    serve_cmd.add_argument("--peer", required=True)
    serve_cmd.add_argument("--room", required=True)
    client_cmd = subs.add_parser("client")
    client_cmd.add_argument("--port", type=int, required=True)
    client_cmd.add_argument("--key", type=Path, required=True)
    client_cmd.add_argument("--server-pin", required=True)
    client_cmd.add_argument("--room", required=True)
    revoke_cmd = subs.add_parser("revoke")
    revoke_cmd.add_argument("--state", type=Path, required=True)
    revoke_cmd.add_argument("--key", type=Path, required=True)
    revoke_cmd.add_argument("--peer", required=True)
    revoke_cmd.add_argument("--room", required=True)
    args = p.parse_args(argv)
    try:
        if args.action == "demo":
            result = demo()
        elif args.action == "serve":
            return serve(args)
        elif args.action == "client":
            result = client(args)
        else:
            gate = Gate(args.state, load_private(args.key), args.peer, args.room)
            gate.revoke()
            result = {"status": "fixture_peer_revoked", "live_xi_connected": False}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Refused, OSError, sqlite3.Error, URLError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc), "live_xi_connected": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
