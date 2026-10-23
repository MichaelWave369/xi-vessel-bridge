"""R3 negative controls. Synthetic peers only; no Xi endpoint, live grant or network."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_peer_r3 import (CrossingError, FixtureReceiver, LocalKeys, ReplayStore,
                        canonical, make_offer, make_receipt, seal)

STAGE = "mutually-approved-synthetic-room"
AT = 1_797_000_000


class R3FixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.phi_keys = LocalKeys.fresh_fixture()
        self.xi_keys = LocalKeys.fresh_fixture()
        self.xi_store = ReplayStore(str(Path(self.tmp.name) / "xi.sqlite3"))
        self.phi_store = ReplayStore(str(Path(self.tmp.name) / "phi.sqlite3"))
        self.xi = self.receiver("xi-fixture", self.xi_keys, {"phi-fixture": self.phi_keys.public()}, self.xi_store)
        self.phi = self.receiver("phi-fixture", self.phi_keys, {"xi-fixture": self.xi_keys.public()}, self.phi_store)
        self.offer = make_offer("⟨ Ξ ⋈ Φ ⟩", {"kind": "ast", "parts": ["bridge", "room"]},
                                {"author": "phi-fixture", "source": "synthetic-demo", "version": "v1",
                                 "intended_use": "local test only"})

    def receiver(self, name, keys, peers, store, *, at=AT):
        return FixtureReceiver(own_id=name, own_keys=keys, pinned_peers=peers,
                               stage=STAGE, store=store, clock=lambda: at)

    def frame(self, payload=None, **kwargs):
        opts = dict(sender="phi-fixture", recipient="xi-fixture", stage=STAGE,
                    sender_keys=self.phi_keys, recipient_public=self.xi_keys.public(),
                    issued_at=AT, ttl=120)
        opts.update(kwargs)
        return seal(self.offer if payload is None else payload, **opts)

    def tearDown(self):
        self.xi_store.close()
        self.phi_store.close()
        self.tmp.cleanup()

    def denied(self, reason, f, receiver=None):
        with self.assertRaises(CrossingError) as cm:
            (receiver or self.xi).open(f)
        self.assertEqual(str(cm.exception), reason)

    def test_reciprocal_authenticated_encrypted_capsule_and_bound_receipt(self):
        sent = self.frame()
        self.assertNotIn(self.offer["xi_text"], json.dumps(sent, ensure_ascii=False))
        accepted = self.xi.open(sent)
        self.assertEqual(accepted["payload"], self.offer)
        self.assertEqual(accepted["sender"], "phi-fixture")
        result = make_receipt(accepted["request_id"], accepted["payload"])
        self.assertEqual(result["offered_payload_sha256"], hashlib.sha256(canonical(self.offer)).hexdigest())
        replied = seal(result, sender="xi-fixture", recipient="phi-fixture", stage=STAGE,
                       sender_keys=self.xi_keys, recipient_public=self.phi_keys.public(), issued_at=AT)
        opened = self.phi.open(replied)
        self.assertEqual(opened["payload"]["in_reply_to"], sent["request_id"])
        self.assertEqual(opened["payload"]["offered_payload_sha256"], accepted["payload_sha256"])
        self.assertTrue(opened["local_only"])

    def test_signature_tampering_refused_before_acceptance(self):
        frame = self.frame()
        for field, value in (("sender", "other"), ("stage", "another"),
                             ("recipient", "other"), ("issued_at", AT - 1)):
            changed = copy.deepcopy(frame)
            changed[field] = value
            self.denied("untrusted_sender" if field == "sender" else
                        "scope_denied" if field in ("stage", "recipient") else
                        "invalid_signature", changed)
        changed = copy.deepcopy(frame)
        changed["ciphertext"] = base64.b64encode(b"bad" * 30).decode()
        self.denied("invalid_signature", changed)
        changed = copy.deepcopy(frame)
        changed["signature"] = base64.b64encode(b"\x00" * 64).decode()
        self.denied("invalid_signature", changed)
        self.assertEqual(self.xi_store.db.execute("SELECT count(*) FROM seen").fetchone()[0], 0)

    def test_untrusted_signer_refused_even_when_sender_name_matches(self):
        attacker = LocalKeys.fresh_fixture()
        sent = self.frame(sender_keys=attacker)
        self.denied("invalid_signature", sent)

    def test_wrong_decryption_identity_denied(self):
        wrong = LocalKeys.fresh_fixture()
        bad = self.frame(recipient_public=wrong.public())
        self.denied("decryption_failed", bad)

    def test_frame_scope_and_expiry_controls(self):
        self.denied("expired_or_future_frame", self.frame(issued_at=AT - 180))
        self.denied("expired_or_future_frame", self.frame(issued_at=AT + 31))
        self.denied("invalid_frame_shape", {**self.frame(), "admin": True})
        f = self.frame(ttl=120)
        f["ttl"] = 301
        self.denied("invalid_timestamp", f)

    def test_replay_and_changed_payload_binding_survive_restart(self):
        first = self.frame()
        self.xi.open(first)
        self.denied("replay_rejected", first)
        second = self.frame(request_id=first["request_id"])
        self.denied("request_id_conflict", second)
        self.xi_store.close()
        self.xi_store = ReplayStore(str(Path(self.tmp.name) / "xi.sqlite3"))
        self.xi = self.receiver("xi-fixture", self.xi_keys, {"phi-fixture": self.phi_keys.public()}, self.xi_store)
        self.denied("replay_rejected", first)
        self.denied("request_id_conflict", second)

    def test_pause_blocks_new_and_replayed_packets(self):
        first = self.frame()
        self.xi.open(first)
        pause = Path(self.tmp.name) / "PAUSED"
        self.xi.pause_file = str(pause)
        pause.touch()
        self.denied("bridge_paused", first)
        self.denied("bridge_paused", self.frame())
        pause.unlink()
        self.denied("replay_rejected", first)

    def test_no_undeclared_history_or_tools_in_capsules(self):
        for extra in ("room_history", "shell_command", "url", "credential"):
            payload = copy.deepcopy(self.offer)
            payload[extra] = "private-or-powerful"
            with self.subTest(field=extra), self.assertRaises(CrossingError):
                self.frame(payload)
        changed = copy.deepcopy(self.offer)
        changed["xi_sha256"] = "0" * 64
        with self.assertRaisesRegex(CrossingError, "xi_hash_mismatch"):
            self.frame(changed)

    def test_semantic_integrity_of_ast_and_provenance(self):
        for part in ("ast", "provenance"):
            altered = copy.deepcopy(self.offer)
            if part == "ast":
                altered["ast"]["parts"].append("altered")
            else:
                altered["provenance"]["author"] = "someone-else"
            received = self.xi.open(self.frame(altered))
            self.assertNotEqual(received["payload_sha256"], hashlib.sha256(canonical(self.offer)).hexdigest())
            self.assertEqual(received["payload"], altered)
        # Deliberately preserve *all* source fields, not silently normalize them.

    def test_rejects_unknown_kind_invalid_receipts_and_expanded_text(self):
        with self.assertRaisesRegex(CrossingError, "unsupported_payload"):
            self.frame({"kind": "tool.execute", "shell": "echo bad"})
        with self.assertRaisesRegex(CrossingError, "invalid_receipt"):
            self.frame({"kind": "capsule.receipt", "in_reply_to": "not-a-uuid",
                        "offered_payload_sha256": "0" * 64, "decision": "fixture_verified"})
        with self.assertRaisesRegex(CrossingError, "invalid_xi_text"):
            make_offer("x" * 4097, {}, self.offer["provenance"])

    def test_each_direction_controls_own_acceptance(self):
        sent = self.frame()
        self.xi.open(sent)
        self.denied("scope_denied", sent, self.phi)
        fake = self.frame(sender="phi-fixture", recipient="xi-fixture", stage="different")
        self.denied("scope_denied", fake)


if __name__ == "__main__":
    unittest.main()
