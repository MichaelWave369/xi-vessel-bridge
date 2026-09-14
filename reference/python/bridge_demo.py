#!/usr/bin/env python3
"""Minimal dependency-free xi.exchange.v1 reference receiver."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


ALLOWED_READ_ONLY = {"artifact.sha256"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now_rfc3339() -> str:
    """Return a JSON-Schema date-time compatible UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class ReferenceReceiver:
    """A tiny receiver demonstrating deny-by-default and request idempotency."""

    system_id: str = "forgecore/reference-b"
    cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    fingerprints: dict[str, str] = field(default_factory=dict)
    execution_counter: int = 0

    @staticmethod
    def _fingerprint(request: dict[str, Any], capsule_bytes: bytes) -> str:
        """Bind replay identity to peer/session semantics, full payload, and exact capsule bytes.

        message_id is intentionally excluded so a transport retry may use a fresh envelope
        message identifier while preserving the same operation request_id.
        """
        security_view = {
            "sender": request.get("sender"),
            "session_id": request.get("session_id"),
            "payload": request.get("payload", {}),
        }
        request_bytes = json.dumps(
            security_view,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        digest = hashlib.sha256()
        digest.update(len(request_bytes).to_bytes(8, "big"))
        digest.update(request_bytes)
        digest.update(len(capsule_bytes).to_bytes(8, "big"))
        digest.update(capsule_bytes)
        return digest.hexdigest()

    def execute(self, request: dict[str, Any], capsule_bytes: bytes) -> dict[str, Any]:
        request_id = request["request_id"]
        payload = request["payload"]
        fingerprint = self._fingerprint(request, capsule_bytes)

        if request_id in self.cache:
            if self.fingerprints[request_id] != fingerprint:
                return self._denied(request, "request_id_conflict")
            return deepcopy(self.cache[request_id])

        if payload.get("permission_requested") != "read_only":
            result = self._denied(request, "permission_not_granted")
            self._remember(request_id, fingerprint, result)
            return deepcopy(result)

        if payload.get("operation") not in ALLOWED_READ_ONLY:
            result = self._denied(request, "operation_not_exposed")
            self._remember(request_id, fingerprint, result)
            return deepcopy(result)

        self.execution_counter += 1
        digest = sha256_bytes(capsule_bytes)
        result = {
            "operation": payload["operation"],
            "status": "completed",
            "output": {"sha256": digest},
            "receipt": {
                "request_id": request_id,
                "operation": payload["operation"],
                "status": "completed",
                "receiver": self.system_id,
                "recorded_at": utc_now_rfc3339(),
                "execution_count": 1,
                "artifact_sha256": digest,
            },
        }
        self._remember(request_id, fingerprint, result)
        return deepcopy(result)

    def _remember(self, request_id: str, fingerprint: str, result: dict[str, Any]) -> None:
        self.fingerprints[request_id] = fingerprint
        self.cache[request_id] = deepcopy(result)

    def _denied(self, request: dict[str, Any], note: str) -> dict[str, Any]:
        operation = request["payload"].get("operation", "unknown")
        return {
            "operation": operation,
            "status": "denied",
            "output": {},
            "receipt": {
                "request_id": request["request_id"],
                "operation": operation,
                "status": "denied",
                "receiver": self.system_id,
                "recorded_at": utc_now_rfc3339(),
                "execution_count": 0,
                "note": note,
            },
        }


def main() -> None:
    capsule = b"Xi Vessel Bridge v0.1 interoperability capsule.\n"
    request = {
        "request_id": "40000000-0000-4000-8000-000000000001",
        "session_id": "20000000-0000-4000-8000-000000000001",
        "sender": {"system": "super-phi-vessel", "instance": "reference-a"},
        "payload": {
            "operation": "artifact.sha256",
            "permission_requested": "read_only",
            "capsule_id": "xi-demo-capsule-001",
            "input": {},
        },
    }
    receiver = ReferenceReceiver()
    first = receiver.execute(request, capsule)
    replay = receiver.execute(request, capsule)

    print("Xi Vessel Bridge v0.1 reference handshake")
    print("status:", first["status"])
    print("sha256:", first["output"]["sha256"])
    print("execution_counter:", receiver.execution_counter)
    print("replay_same_result:", first == replay)


if __name__ == "__main__":
    main()
