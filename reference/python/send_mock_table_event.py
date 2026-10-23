#!/usr/bin/env python3
"""Send a synthetic signed Xi Table mention to the localhost staging receiver."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser(description="Xi Table R1 staging event simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8769/v1/xi/events")
    parser.add_argument("--room", default="local-staging-room")
    parser.add_argument("--message", default="Hello @Phi, are you at the Table?")
    args = parser.parse_args()
    # Prevent accidentally pushing synthetic events to a remote host.
    from urllib.parse import urlparse
    endpoint = urlparse(args.url)
    if (endpoint.scheme != "http" or endpoint.hostname not in
            {"127.0.0.1", "localhost", "::1"}):
        parser.error("synthetic event sender is restricted to localhost HTTP")
    secret = os.getenv("XI_TABLE_WEBHOOK_SECRET", "").encode("utf-8")
    if len(secret) < 32:
        parser.error("set XI_TABLE_WEBHOOK_SECRET to at least 32 bytes")
    event = {
        "schema": "xi.table.mention.mock.v1",
        "event_id": str(uuid4()),
        "room_id": args.room,
        "message_id": str(uuid4()),
        "kind": "mention",
        "target_seat": "Phi",
        "sender": {"seat_id": "staging-human", "display_name": "Local tester"},
        "body": args.message,
    }
    raw = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = str(int(time.time()))
    signature = "sha256=" + hmac.new(
        secret, timestamp.encode("ascii") + b"." + raw, hashlib.sha256
    ).hexdigest()
    request = urllib.request.Request(
        args.url, data=raw, method="POST",
        headers={"Content-Type": "application/json", "X-Xi-Timestamp": timestamp,
                 "X-Xi-Signature": signature},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as result:
            print(result.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(exc.read().decode("utf-8"))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
