#!/usr/bin/env python3
"""R5 dynamic local operator grant demo. NO REAL XI PERMISSIONS OR KEYS."""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from demo_peer_r4 import fixture_profiles, start_fixture_server
from xi_peer_r3 import make_offer, seal
from xi_peer_r4_http import PATH, exchange, post_loopback, read_fixture_profile
from xi_peer_r5_policy import atomic_write_fixture_grant, fixture_grant

STAGE = "agreed-r5-local-fixture"


def main():
    with tempfile.TemporaryDirectory(prefix="xi-phi-r5-") as root:
        directory = Path(root)
        phi_file, xi_file = fixture_profiles(directory)
        phi = read_fixture_profile(str(phi_file))
        grant_file = directory / "operator-grant.json"
        proc, port = start_fixture_server(xi_file, directory, stage=STAGE,
                                          grant_file=grant_file)
        url = f"http://127.0.0.1:{port}{PATH}"
        offer = make_offer("⟨ Ξ ⋈ Φ ⟩", {"node": "fixture-capsule"},
                           {"author": phi.local_id, "source": "r5-demo",
                            "version": "r5", "intended_use": "offline authorization test"})
        try:
            # No grant: even a valid signature gives no execution authority.
            first = seal(offer, sender=phi.local_id, recipient=phi.peer_id,
                         stage=STAGE, sender_keys=phi.keys,
                         recipient_public=phi.peer)
            status, result = post_loopback(url, first)
            if (status, result.get("reason")) != (503, "grant_missing"):
                raise RuntimeError("missing-grant control failed")
            at = int(time.time())
            grant = fixture_grant(sender=phi.local_id, recipient=phi.peer_id,
                                  stage=STAGE, not_before=at - 10,
                                  expires_at=at + 120)
            atomic_write_fixture_grant(str(grant_file), grant)
            # The previously denied request was not consumed by replay storage.
            status, result = post_loopback(url, first)
            if status != 200 or result.get("mode") != "fixture_only":
                raise RuntimeError("explicit-grant admission failed")
            accepted = exchange(phi, STAGE, url, offer)
            if not accepted["receipt_matches_offer"]:
                raise RuntimeError("receipt verification failed")
            # Revocation takes effect immediately, without server or model restart.
            grant["revoked"] = True
            atomic_write_fixture_grant(str(grant_file), grant)
            status, result = post_loopback(url, first)
            if (status, result.get("reason")) != (403, "grant_revoked"):
                raise RuntimeError("revocation did not stop replay")
            status, result = post_loopback(
                url, seal(offer, sender=phi.local_id, recipient=phi.peer_id,
                          stage=STAGE, sender_keys=phi.keys,
                          recipient_public=phi.peer))
            if (status, result.get("reason")) != (403, "grant_revoked"):
                raise RuntimeError("revocation did not stop new requests")
            print(json.dumps({
                "status": "R5_LOCAL_GRANT_LIFECYCLE_VERIFIED",
                "no_grant_denied": True,
                "explicit_grant_accepted": True,
                "cryptographic_receipt_verified": True,
                "revocation_without_restart": True,
                "live_xi_connected": False
            }, indent=2))
        finally:
            proc.terminate()
            try:
                proc.communicate(timeout=5)
            except Exception:
                proc.kill()
                proc.communicate(timeout=5)


if __name__ == "__main__":
    main()
