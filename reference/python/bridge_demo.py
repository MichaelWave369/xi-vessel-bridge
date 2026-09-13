#!/usr/bin/env python3
"""Minimal dependency-free xi.exchange.v1 reference receiver."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


ALLOWED_READ_ONLY = {"artifact.sha256"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class ReferenceReceiver:
    """A tiny receiver demonstrating deny-by-default and request idempotency."""

    system_id: str = "forgecore/reference-b"
    cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    fingerprints: dict[str, str] = field(default_factory=dict)
    execution_counter: int = 0

    @staticmethod
    def _fingerprint(request: dict[str, Any]) -> str:
        # The demo only needs a stable fingerprint for its narrow request shape.
        payload = request["payload"]
        stable = "|".join(
            [
                request["request_id"],
                payload["operation"],
                payload["permission_requested"],
                payload.get("capsule_id", ""),
            ]
        )
        return sha256_bytes(stable.encode("utf-8"))

    def execute(self, request: dict[str, Any], capsule_bytes: bytes) -> dict[str, Any]:
        request_id = request["request_id"]
        payload = request["payload"]
        fingerprint = self._fingerprint(request)

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
                "recorded_at": "reference-runtime",
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
                "recorded_at": "reference-runtime",
                "execution_count": 0,
                "note": note,
            },
        }


def main() -> None:
    capsule = b"Xi Vessel Bridge v0.1 interoperability capsule.\n"
    request = {
        "request_id": "40000000-0000-4000-8000-000000000001",
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
