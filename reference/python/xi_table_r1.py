#!/usr/bin/env python3
"""Xi Table -> Phi staging bridge. No production Xi or Phi connection is implied.

Only authenticated, explicit Phi mentions in the synthetic v0 event shape are
accepted. The reply is a local mock; this module never calls a remote runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID

SCHEMA = "xi.table.mention.mock.v1"
MAX_BYTES = 16_384
MAX_SKEW_SECONDS = 300
ALLOWED_FIELDS = {"schema", "event_id", "room_id", "message_id", "kind",
                  "target_seat", "sender", "body"}


class BridgeError(Exception):
    def __init__(self, code: str, http_status: int = 422):
        super().__init__(code)
        self.code = code
        self.http_status = http_status


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def validate_event(event: object, allowed_room: str | None) -> dict:
    if not isinstance(event, dict) or set(event) != ALLOWED_FIELDS:
        raise BridgeError("invalid_event_shape")
    if event["schema"] != SCHEMA or event["kind"] != "mention":
        raise BridgeError("unsupported_event")
    if not _uuid(event["event_id"]) or not _uuid(event["message_id"]):
        raise BridgeError("invalid_ids")
    room = event["room_id"]
    if not isinstance(room, str) or not 1 <= len(room) <= 100:
        raise BridgeError("invalid_room")
    if allowed_room is not None and room != allowed_room:
        raise BridgeError("room_not_allowed", 403)
    seat = event["target_seat"]
    if not isinstance(seat, str) or not 1 <= len(seat) <= 64:
        raise BridgeError("invalid_target")
    sender = event["sender"]
    if (not isinstance(sender, dict) or set(sender) != {"seat_id", "display_name"}
            or not isinstance(sender["seat_id"], str)
            or not 1 <= len(sender["seat_id"]) <= 100
            or not isinstance(sender["display_name"], str)
            or not 1 <= len(sender["display_name"]) <= 100):
        raise BridgeError("invalid_sender")
    body = event["body"]
    if not isinstance(body, str) or not 1 <= len(body.strip()) <= 4000:
        raise BridgeError("invalid_body")
    return event


class DurableEventStore:
    """SQLite reservation prevents repeated processing across restarts/processes.

    A crash during an in-progress reservation intentionally does NOT retry
    automatically. A future real posting adapter must use downstream idempotency.
    """

    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False,
                                  isolation_level=None)
        self.lock = threading.RLock()
        with self.lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS events ("
                            "event_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, "
                            "state TEXT NOT NULL, result_json TEXT)")

    def reserve(self, event_id: str, fingerprint: str) -> tuple[str, dict | None]:
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT fingerprint, state, result_json FROM events WHERE event_id=?",
                    (event_id,)).fetchone()
                if row:
                    state = ("conflict" if row[0] != fingerprint else
                             "duplicate" if row[1] == "completed" else "in_progress")
                    data = json.loads(row[2]) if state == "duplicate" else None
                    self.db.execute("COMMIT")
                    return state, data
                self.db.execute("INSERT INTO events VALUES (?, ?, 'pending', NULL)",
                                (event_id, fingerprint))
                self.db.execute("COMMIT")
                return "new", None
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def finish(self, event_id: str, result: dict) -> None:
        with self.lock:
            self.db.execute(
                "UPDATE events SET state='completed', result_json=? "
                "WHERE event_id=? AND state='pending'",
                (json.dumps(result, separators=(",", ":")), event_id))

    def count(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self) -> None:
        with self.lock:
            self.db.close()


class XiTableStagingBridge:
    def __init__(self, secret: bytes, state_db: str,
                 allowed_room: str | None = None, clock=time.time):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("XI_TABLE_WEBHOOK_SECRET must contain at least 32 bytes")
        self.secret = secret
        self.allowed_room = allowed_room
        self.clock = clock
        self.store = DurableEventStore(state_db)

    def signed(self, raw: bytes, timestamp: str) -> str:
        """Developer/test sender helper, not a claim about Hunter's API format."""
        mac = hmac.new(self.secret, timestamp.encode("ascii") + b"." + raw,
                       hashlib.sha256).hexdigest()
        return "sha256=" + mac

    def handle(self, raw: bytes, timestamp: str | None,
               signature: str | None) -> tuple[int, dict]:
        try:
            if not raw or len(raw) > MAX_BYTES:
                raise BridgeError("invalid_body_size", 413)
            if not isinstance(timestamp, str) or not timestamp.isascii() or not timestamp.isdigit():
                raise BridgeError("invalid_timestamp", 401)
            if abs(self.clock() - int(timestamp)) > MAX_SKEW_SECONDS:
                raise BridgeError("expired_timestamp", 401)
            if not isinstance(signature, str) or not hmac.compare_digest(
                    self.signed(raw, timestamp), signature):
                raise BridgeError("invalid_signature", 401)
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise BridgeError("invalid_json") from None
            event = validate_event(event, self.allowed_room)
            if event["target_seat"].casefold() != "phi":
                return 200, {"status": "ignored", "reason": "not_addressed_to_phi"}

            fingerprint = hashlib.sha256(raw).hexdigest()
            state, prior = self.store.reserve(event["event_id"], fingerprint)
            if state == "conflict":
                raise BridgeError("event_id_conflict", 409)
            if state == "in_progress":
                return 202, {"status": "in_progress", "event_id": event["event_id"]}
            if state == "duplicate":
                return 200, {"status": "duplicate", "result": prior}

            # Mock-only. No model invocation, real-room posting or message-history reads.
            result = {
                "status": "mock_completed",
                "reply": {
                    "seat": "Phi",
                    "reply_to": event["message_id"],
                    "text": "Φ staging ACK: signed mention received. No live model was called.",
                    "mode": "mock_only",
                },
                "receipt": {
                    "event_id": event["event_id"],
                    "request_id": event["event_id"],
                    "operation": "xi.table.mock_mention",
                    "receiver": "xi-vessel-bridge/r1",
                    "status": "mock_completed",
                    "recorded_at": utc_timestamp(),
                    "event_sha256": fingerprint,
                },
            }
            self.store.finish(event["event_id"], result)
            return 200, result
        except BridgeError as exc:
            return exc.http_status, {"status": "denied", "reason": exc.code}


def make_handler(bridge: XiTableStagingBridge):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Never print headers, body, message contents, or credentials.
            return

        def reply(self, status: int, obj: dict):
            body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path != "/healthz":
                return self.reply(404, {"status": "denied", "reason": "not_found"})
            self.reply(200, {"status": "staging_only", "live_connection": False})

        def do_POST(self):
            if self.path != "/v1/xi/events":
                return self.reply(404, {"status": "denied", "reason": "not_found"})
            if self.headers.get("Transfer-Encoding"):
                return self.reply(400, {"status": "denied", "reason": "unsupported_transfer"})
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                return self.reply(415, {"status": "denied", "reason": "unsupported_content_type"})
            try:
                n = int(self.headers.get("Content-Length", ""))
            except ValueError:
                n = 0
            if not 0 < n <= MAX_BYTES:
                return self.reply(413, {"status": "denied", "reason": "invalid_body_size"})
            raw = self.rfile.read(n)
            status, obj = bridge.handle(raw, self.headers.get("X-Xi-Timestamp"),
                                        self.headers.get("X-Xi-Signature"))
            self.reply(status, obj)

    return Handler


def main():
    parser = argparse.ArgumentParser(description="LOCAL staging-only Xi Table mock bridge")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8769)
    parser.add_argument("--state-db", default=".xi-table-state/events.sqlite3")
    parser.add_argument("--room", default=os.getenv("XI_TABLE_ALLOWED_ROOM"))
    args = parser.parse_args()
    secret = os.getenv("XI_TABLE_WEBHOOK_SECRET", "").encode("utf-8")
    bridge = XiTableStagingBridge(secret, args.state_db, args.room)
    # Never publish this service publicly without a separate TLS/reverse-proxy,
    # authentication, rate-limiting and real Xi event-contract review.
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(bridge))
    print(f"Xi Table R1 MOCK listener on {args.host}:{args.port} (not connected to Xi)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        bridge.store.close()


if __name__ == "__main__":
    main()
