#!/usr/bin/env python3
"""R4: two-process, loopback-only, sealed Xi/Phi FIXTURE transport.

NOT Xi's real API, native TESSERA codec, or an internet listener. This
module never contacts an external host, executes a model, or posts to a room.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from xi_peer_r3 import (
    CrossingError, FixtureReceiver, LocalKeys, PeerIdentity, ReplayStore,
    _unb64, canonical, make_offer, make_receipt, seal,
)

PATH = "/v1/fixture/capsule"
MAX_HTTP_BYTES = 16_384
PROFILE_FIELDS = {
    "fixture_only", "local_id", "peer_id", "sign_private_b64",
    "decrypt_private_b64", "peer_sign_public_b64", "peer_decrypt_public_b64",
}


@dataclass(frozen=True)
class Profile:
    local_id: str
    peer_id: str
    keys: LocalKeys
    peer: PeerIdentity


def strict_json(raw: bytes):
    def unique(pairs):
        output = {}
        for k, value in pairs:
            if k in output:
                raise ValueError("duplicate_json_key")
            output[k] = value
        return output
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite")))


def read_fixture_profile(path: str) -> Profile:
    """Open an explicit private fixture file without following final symlinks.

    Owner-only mode check is available on POSIX. No production key protection
    or Windows ACL validation is claimed. Profiles MUST contain disposable
    locally generated fixture keys, never Xi tessera material.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CrossingError("unreadable_fixture_profile") from exc
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > 4096 or meta.st_size < 10:
            raise CrossingError("invalid_fixture_profile_file")
        if os.name == "posix" and meta.st_mode & 0o077:
            raise CrossingError("insecure_fixture_profile_permissions")
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    try:
        data = strict_json(raw)
        if not isinstance(data, dict) or set(data) != PROFILE_FIELDS or data["fixture_only"] is not True:
            raise CrossingError("invalid_fixture_profile")
        own, peer = data["local_id"], data["peer_id"]
        if (not isinstance(own, str) or not isinstance(peer, str) or own == peer
                or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}-fixture", own)
                or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}-fixture", peer)):
            raise CrossingError("invalid_fixture_ids")
        keys = LocalKeys(
            Ed25519PrivateKey.from_private_bytes(_unb64(data["sign_private_b64"], 32)),
            X25519PrivateKey.from_private_bytes(_unb64(data["decrypt_private_b64"], 32)))
        remote = PeerIdentity(
            Ed25519PublicKey.from_public_bytes(_unb64(data["peer_sign_public_b64"], 32)),
            X25519PublicKey.from_public_bytes(_unb64(data["peer_decrypt_public_b64"], 32)))
        return Profile(own, peer, keys, remote)
    except (ValueError, TypeError, KeyError) as exc:
        raise CrossingError("invalid_fixture_profile") from exc


def validate_loopback_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        if (parts.scheme != "http" or parts.hostname != "127.0.0.1"
                or parts.username is not None or parts.password is not None
                or parts.path != PATH or parts.query or parts.fragment
                or parts.port is None or not 1 <= parts.port <= 65535
                or parts.netloc != "127.0.0.1:" + str(parts.port)):
            raise ValueError()
    except ValueError as exc:
        raise CrossingError("loopback_url_required") from exc
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post_loopback(url: str, frame: dict) -> tuple[int, dict]:
    validate_loopback_url(url)
    raw = canonical(frame)
    if len(raw) > MAX_HTTP_BYTES:
        raise CrossingError("frame_too_large")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, method="POST", data=raw, headers={
        "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with opener.open(request, timeout=4) as response:
            body, status = response.read(MAX_HTTP_BYTES + 1), response.status
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read(MAX_HTTP_BYTES + 1)
    if len(body) > MAX_HTTP_BYTES:
        raise CrossingError("response_too_large")
    try:
        result = strict_json(body)
        if not isinstance(result, dict):
            raise ValueError()
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CrossingError("invalid_response") from exc
    return status, result


def make_handler(receiver: FixtureReceiver, profile: Profile):
    """Endpoint is intentionally hard-coded. No arbitrary tool dispatch."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            # No endpoint, headers, body, identifiers, or credentials in logs.
            pass

        def reply(self, status: int, body: dict):
            data = canonical(body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path != "/healthz":
                return self.reply(404, {"status": "denied", "reason": "not_found"})
            paused = receiver.is_paused() if hasattr(receiver, "is_paused") else (
                bool(receiver.pause_file and Path(receiver.pause_file).exists()))
            self.reply(200, {"status": "paused" if paused else "fixture_only",
                             "live_xi_connected": False, "paused": paused})

        def do_POST(self):
            if self.path != PATH:
                return self.reply(404, {"status": "denied", "reason": "not_found"})
            if receiver.pause_file:
                try:
                    if Path(receiver.pause_file).exists():
                        return self.reply(503, {"status": "denied", "reason": "bridge_paused"})
                except OSError:
                    return self.reply(503, {"status": "denied", "reason": "pause_check_failed"})
            if self.headers.get("Transfer-Encoding") or self.headers.get("Expect"):
                return self.reply(400, {"status": "denied", "reason": "unsupported_transfer"})
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                return self.reply(415, {"status": "denied", "reason": "content_type_required"})
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
                return self.reply(400, {"status": "denied", "reason": "invalid_content_length"})
            n = int(lengths[0])
            if not 0 < n <= MAX_HTTP_BYTES:
                return self.reply(413, {"status": "denied", "reason": "invalid_body_size"})
            raw = self.rfile.read(n)
            if len(raw) != n:
                return self.reply(400, {"status": "denied", "reason": "incomplete_body"})
            try:
                frame = strict_json(raw)
                if not isinstance(frame, dict):
                    raise CrossingError("invalid_frame")
                opened = receiver.open(frame)
                if opened["payload"]["kind"] != "capsule.offer":
                    raise CrossingError("offer_only")
                receipt = make_receipt(opened["request_id"], opened["payload"])
                sealed = seal(receipt, sender=profile.local_id, recipient=profile.peer_id,
                              stage=receiver.stage, sender_keys=profile.keys,
                              recipient_public=profile.peer)
                return self.reply(200, {"receipt_frame": sealed, "mode": "fixture_only"})
            except (CrossingError, UnicodeError, ValueError, TypeError) as exc:
                reason = str(exc) if isinstance(exc, CrossingError) else "invalid_json"
                status = 409 if reason in {"replay_rejected", "request_id_conflict"} else (
                    503 if reason.startswith("pause_") or reason in {"bridge_paused", "grant_missing", "grant_invalid", "grant_ledger_unavailable"} else 403)
                return self.reply(status, {"status": "denied", "reason": reason})

    return Handler


def make_server(profile: Profile, stage: str, store: ReplayStore, pause_file: str,
                port: int = 0, authorize=None) -> tuple[HTTPServer, FixtureReceiver]:
    if not isinstance(stage, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,80}", stage):
        raise CrossingError("invalid_fixture_stage")
    receiver = FixtureReceiver(
        own_id=profile.local_id, own_keys=profile.keys,
        pinned_peers={profile.peer_id: profile.peer}, stage=stage,
        store=store, pause_file=pause_file, authorize=authorize)
    # Only explicit numeric IPv4 loopback, even if caller supplies a URL.
    server = HTTPServer(("127.0.0.1", port), make_handler(receiver, profile))
    return server, receiver


def exchange(profile: Profile, stage: str, url: str, offer: dict) -> dict:
    frame = seal(offer, sender=profile.local_id, recipient=profile.peer_id,
                 stage=stage, sender_keys=profile.keys, recipient_public=profile.peer)
    status, body = post_loopback(url, frame)
    if status != 200 or set(body) != {"receipt_frame", "mode"} or body["mode"] != "fixture_only":
        raise CrossingError("peer_refused_fixture")
    receipt_store = ReplayStore(":memory:")
    try:
        local = FixtureReceiver(own_id=profile.local_id, own_keys=profile.keys,
                                pinned_peers={profile.peer_id: profile.peer}, stage=stage,
                                store=receipt_store)
        received = local.open(body["receipt_frame"])
        expected = hashlib.sha256(canonical(offer)).hexdigest()
        actual = received["payload"]
        if (actual["kind"] != "capsule.receipt"
                or actual["in_reply_to"] != frame["request_id"]
                or actual["offered_payload_sha256"] != expected
                or actual["decision"] != "fixture_verified"):
            raise CrossingError("unbound_receipt")
        return {"status": "R4_TWO_PROCESS_FIXTURE_VERIFIED", "receipt_matches_offer": True,
                "live_xi_connected": False}
    finally:
        receipt_store.close()


def main():
    parser = argparse.ArgumentParser(description="Xi/Phi R4 LOCAL-ONLY fixture process")
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--profile", required=True, help="Private disposable fixture profile (0600 on POSIX)")
    parser.add_argument("--stage", required=True, help="Identical, manually accepted synthetic stage")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--url", default=None, help="Client only, 127.0.0.1 and fixed path")
    parser.add_argument("--state-dir", default=".xi-peer-state/r4-fixture")
    parser.add_argument("--grant-file", default=None, help="Server-only operator grant policy")
    parser.add_argument("--grant-ledger", default=None, help="Server-only R6 durable revocation DB")
    args = parser.parse_args()
    profile = read_fixture_profile(args.profile)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,80}", args.stage):
        parser.error("invalid_fixture_stage")
    if args.mode == "server":
        if args.url or not 0 <= args.port <= 65535:
            parser.error("server accepts only a numeric loopback port")
        directory = Path(args.state_dir)
        directory.mkdir(parents=True, exist_ok=True)
        store = ReplayStore(str(directory / "requests.sqlite3"))
        if args.grant_ledger and not args.grant_file:
            parser.error("--grant-ledger requires --grant-file")
        gate = None
        if args.grant_ledger:
            from xi_peer_r6_ledger import MonotonicGrantGate
            gate = MonotonicGrantGate(args.grant_file, args.grant_ledger)
        elif args.grant_file:
            from xi_peer_r5_policy import OperatorGrantGate
            gate = OperatorGrantGate(args.grant_file)
        server, _ = make_server(profile, args.stage, store, str(directory / "PAUSED"), args.port,
                                authorize=gate)
        print(json.dumps({"status": "R4_FIXTURE_LISTENING", "port": server.server_port,
                          "live_xi_connected": False}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            store.close()
            if gate is not None and hasattr(gate, "close"):
                gate.close()
    else:
        if args.grant_file or args.grant_ledger:
            parser.error("--grant-file and --grant-ledger apply only to the server")
        if not args.url:
            parser.error("client needs an explicit --url")
        try:
            validate_loopback_url(args.url)
            offer = make_offer("⟨ Ξ ⋈ Φ ⟩", {"type": "synthetic-node", "nodes": ["Xi", "Phi"]},
                               {"author": profile.local_id, "source": "offline-r4-demo",
                                "version": "r4-fixture", "intended_use": "local transport acceptance"})
            print(json.dumps(exchange(profile, args.stage, args.url, offer)), flush=True)
        except (CrossingError, urllib.error.URLError) as exc:
            parser.error("fixture crossing failed: " +
                         (str(exc) if isinstance(exc, CrossingError) else "loopback_connection_error"))


if __name__ == "__main__":
    main()
