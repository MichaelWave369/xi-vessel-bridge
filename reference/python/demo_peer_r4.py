#!/usr/bin/env python3
"""Run independent Phi client and Xi server subprocesses. LOCAL TESTS ONLY."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from xi_peer_r3 import LocalKeys, public_bytes

HERE = Path(__file__).resolve().parent


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def private_bytes(key) -> bytes:
    return key.private_bytes(encoding=serialization.Encoding.Raw,
                             format=serialization.PrivateFormat.Raw,
                             encryption_algorithm=serialization.NoEncryption())


def make_profile(path: Path, own: str, mine: LocalKeys, peer: str, other: LocalKeys):
    data = {
        "fixture_only": True, "local_id": own, "peer_id": peer,
        "sign_private_b64": b64(private_bytes(mine.sign_private)),
        "decrypt_private_b64": b64(private_bytes(mine.decrypt_private)),
        "peer_sign_public_b64": b64(public_bytes(other.sign_private.public_key())),
        "peer_decrypt_public_b64": b64(public_bytes(other.decrypt_private.public_key())),
    }
    # Explicit create-only, private file. Never commit, log or upload it.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, separators=(",", ":"))
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def fixture_profiles(directory: Path) -> tuple[Path, Path]:
    phi, xi = LocalKeys.fresh_fixture(), LocalKeys.fresh_fixture()
    phi_file, xi_file = directory / "phi-fixture.private.json", directory / "xi-fixture.private.json"
    make_profile(phi_file, "phi-fixture", phi, "xi-fixture", xi)
    make_profile(xi_file, "xi-fixture", xi, "phi-fixture", phi)
    return phi_file, xi_file


def start_fixture_server(profile: Path, directory: Path, *, stage: str):
    proc = subprocess.Popen(
        [sys.executable, "-u", str(HERE / "xi_peer_r4_http.py"), "server",
         "--profile", str(profile), "--stage", stage, "--port", "0",
         "--state-dir", str(directory / "server-state")],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8")
    try:
        # The very first line is a bounded, credential-free readiness record.
        line = proc.stdout.readline(512)
        ready = json.loads(line)
        if ready["status"] != "R4_FIXTURE_LISTENING":
            raise ValueError("unexpected_ready_record")
        return proc, int(ready["port"])
    except BaseException:
        proc.kill()
        proc.communicate(timeout=5)
        raise RuntimeError("fixture server did not start; no secret logged") from None


def main():
    with tempfile.TemporaryDirectory(prefix="xi-phi-r4-") as root:
        directory = Path(root)
        phi, xi = fixture_profiles(directory)
        stage = "agreed-fixture-only-stage"
        proc, port = start_fixture_server(xi, directory, stage=stage)
        try:
            completed = subprocess.run(
                [sys.executable, str(HERE / "xi_peer_r4_http.py"), "client",
                 "--profile", str(phi), "--stage", stage,
                 "--url", f"http://127.0.0.1:{port}/v1/fixture/capsule"],
                capture_output=True, text=True, check=False, timeout=10)
            if completed.returncode != 0:
                raise RuntimeError("fixture client failed; inspect offline CI tests")
            result = json.loads(completed.stdout)
            if result != {"status": "R4_TWO_PROCESS_FIXTURE_VERIFIED",
                           "receipt_matches_offer": True, "live_xi_connected": False}:
                raise RuntimeError("unexpected_fixture_result")
            print(json.dumps(result, indent=2))
        finally:
            proc.terminate()
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=5)


if __name__ == "__main__":
    main()
