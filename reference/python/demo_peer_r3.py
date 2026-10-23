#!/usr/bin/env python3
"""Demonstrate a reciprocal SEALED crossing using only disposable local keys."""
from __future__ import annotations

import json
from xi_peer_r3 import (FixtureReceiver, LocalKeys, ReplayStore,
                        make_offer, make_receipt, seal)


def main():
    phi_keys, xi_keys = LocalKeys.fresh_fixture(), LocalKeys.fresh_fixture()
    phi_store, xi_store = ReplayStore(":memory:"), ReplayStore(":memory:")
    try:
        phi = FixtureReceiver(own_id="phi-fixture", own_keys=phi_keys,
                              pinned_peers={"xi-fixture": xi_keys.public()},
                              stage="mutually-approved-synthetic-room", store=phi_store)
        xi = FixtureReceiver(own_id="xi-fixture", own_keys=xi_keys,
                             pinned_peers={"phi-fixture": phi_keys.public()},
                             stage="mutually-approved-synthetic-room", store=xi_store)
        offer = make_offer("⟨ Ξ ⋈ Φ ⟩", {"node": "tessera", "members": ["Xi", "Phi"]},
                           {"author": "phi-fixture", "source": "local-demo", "version": "1",
                            "intended_use": "offline test"})
        sent = seal(offer, sender="phi-fixture", recipient="xi-fixture", sender_keys=phi_keys,
                    recipient_public=xi_keys.public(), stage="mutually-approved-synthetic-room")
        received = xi.open(sent)
        receipt = make_receipt(received["request_id"], received["payload"])
        reply = seal(receipt, sender="xi-fixture", recipient="phi-fixture", sender_keys=xi_keys,
                     recipient_public=phi_keys.public(), stage="mutually-approved-synthetic-room")
        confirmed = phi.open(reply)
        assert confirmed["payload"]["in_reply_to"] == sent["request_id"]
        assert confirmed["payload"]["offered_payload_sha256"] == received["payload_sha256"]
        print(json.dumps({"result": "OFFLINE_RECIPROCAL_FIXTURE_VERIFIED",
                          "seal": "X25519 ephemeral + HKDF + AES-256-GCM + Ed25519",
                          "request_id": sent["request_id"],
                          "receipt_matches_offer": True, "real_xi_connected": False}, indent=2))
    finally:
        phi_store.close()
        xi_store.close()


if __name__ == "__main__":
    main()
