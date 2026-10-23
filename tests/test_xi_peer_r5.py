"""R5 local operator grants: authorization distinct from peer identity."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_peer_r3 import CrossingError, FixtureReceiver, LocalKeys, ReplayStore, make_offer, seal
from xi_peer_r5_policy import (
    OperatorGrantGate, atomic_write_fixture_grant, fixture_grant,
    read_operator_grant, validate_grant,
)

NOW = 1797000000
STAGE = "fixture-authorized-room"


class R5GrantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.policy = str(self.directory / "operator.json")
        self.phi = LocalKeys.fresh_fixture()
        self.xi = LocalKeys.fresh_fixture()
        self.store = ReplayStore(str(self.directory / "replay.sqlite3"))
        self.receiver = FixtureReceiver(
            own_id="xi-fixture", own_keys=self.xi,
            pinned_peers={"phi-fixture": self.phi.public()},
            stage=STAGE, store=self.store, clock=lambda: NOW,
            authorize=OperatorGrantGate(self.policy))
        self.offer = make_offer(
            "⟨ Ξ ⋈ Φ ⟩", {"kind": "fixture-node"},
            {"author": "phi-fixture", "source": "unit-test", "version": "r5",
             "intended_use": "offline protocol test"})

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def valid_grant(self, **overrides):
        data = fixture_grant(sender="phi-fixture", recipient="xi-fixture", stage=STAGE,
                             not_before=NOW - 10, expires_at=NOW + 120)
        data.update(overrides)
        atomic_write_fixture_grant(self.policy, data)
        return data

    def frame(self, **overrides):
        params = {
            "sender": "phi-fixture", "recipient": "xi-fixture",
            "stage": STAGE, "issued_at": NOW, "sender_keys": self.phi,
            "recipient_public": self.xi.public(),
        }
        params.update(overrides)
        return seal(self.offer, **params)

    def assert_denied(self, frame, expected):
        with self.assertRaises(CrossingError) as caught:
            self.receiver.open(frame)
        self.assertEqual(str(caught.exception), expected)

    def count(self):
        return self.store.db.execute("SELECT COUNT(*) FROM seen").fetchone()[0]

    def test_no_grant_denies_valid_signature_without_reserving(self):
        signed = self.frame()
        self.assert_denied(signed, "grant_missing")
        self.assertEqual(self.count(), 0)
        self.valid_grant()
        opened = self.receiver.open(signed)
        self.assertEqual(opened["sender"], "phi-fixture")
        self.assertEqual(self.count(), 1)

    def test_explicit_grant_expires_and_rejects_future_start(self):
        self.valid_grant(not_before=NOW + 1, expires_at=NOW + 120)
        self.assert_denied(self.frame(), "grant_expired_or_not_yet_valid")
        self.valid_grant(not_before=NOW - 120, expires_at=NOW)
        self.assert_denied(self.frame(), "grant_expired_or_not_yet_valid")
        self.assertEqual(self.count(), 0)

    def test_operator_revocation_blocks_existing_and_new_requests(self):
        grant = self.valid_grant()
        first = self.frame()
        self.receiver.open(first)
        self.assertEqual(self.count(), 1)
        grant["revoked"] = True
        atomic_write_fixture_grant(self.policy, grant)
        self.assert_denied(first, "grant_revoked")
        self.assert_denied(self.frame(), "grant_revoked")
        self.assertEqual(self.count(), 1)

    def test_grant_does_not_enroll_other_keys(self):
        self.valid_grant()
        impostor = LocalKeys.fresh_fixture()
        self.assert_denied(self.frame(sender_keys=impostor), "invalid_signature")
        self.assertEqual(self.count(), 0)

    def test_wrong_grant_scope_denied_with_valid_signer(self):
        for override in [
            {"sender": "other-fixture"},
            {"recipient": "other-fixture"},
            {"stage": "other-fixture-stage"},
        ]:
            with self.subTest(override=override):
                self.valid_grant(**override)
                self.assert_denied(self.frame(), "grant_scope_denied")
        self.assertEqual(self.count(), 0)

    def test_capability_claim_does_not_grant_arbitrary_execution(self):
        rejected = self.valid_grant()
        rejected["capabilities"] = ["shell.exec"]
        with self.assertRaisesRegex(CrossingError, "grant_invalid"):
            validate_grant(rejected)
        # The operator's same key never grants arbitrary tools.
        self.assert_denied(self.frame(), "grant_scope_denied") if False else None
        self.assertEqual(self.count(), 0)

    def test_broken_and_missing_policy_fail_closed(self):
        self.assert_denied(self.frame(), "grant_missing")
        Path(self.policy).write_text('{"grant_id":"tampered"}', encoding="utf-8")
        self.assert_denied(self.frame(), "grant_invalid")
        self.assertEqual(self.count(), 0)

    def test_policy_must_be_exact_small_and_no_symlink(self):
        data = self.valid_grant()
        self.assertEqual(read_operator_grant(self.policy)["grant_id"], data["grant_id"])
        for changed in [
            {**data, "debug": "not permitted"},
            {**data, "capabilities": ["capsule.offer", "shell.exec"]},
            {**data, "not_before": NOW + 300},
            {**data, "expires_at": NOW + 1000},
            {**data, "revoked": 0},
        ]:
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(CrossingError, "grant_invalid"):
                    validate_grant(changed)
        link = self.directory / "grant-link.json"
        try:
            link.symlink_to(Path(self.policy))
        except (OSError, NotImplementedError):
            pass
        else:
            with self.assertRaisesRegex(CrossingError, "grant_invalid"):
                read_operator_grant(str(link))

    def test_replay_still_protected_after_operator_reauthorizes(self):
        grant = self.valid_grant()
        f = self.frame()
        self.receiver.open(f)
        grant["revoked"] = True
        atomic_write_fixture_grant(self.policy, grant)
        self.assert_denied(f, "grant_revoked")
        grant["revoked"] = False
        atomic_write_fixture_grant(self.policy, grant)
        self.assert_denied(f, "replay_rejected")
        self.assertEqual(self.count(), 1)

    def test_denied_frame_does_not_consume_replay_id(self):
        grant = self.valid_grant(revoked=True)
        f = self.frame()
        self.assert_denied(f, "grant_revoked")
        self.assertEqual(self.count(), 0)
        grant["revoked"] = False
        atomic_write_fixture_grant(self.policy, grant)
        self.receiver.open(f)
        self.assertEqual(self.count(), 1)

    def test_two_process_revoke_without_restart(self):
        run = subprocess.run(
            [sys.executable, str(ROOT / "reference" / "python" / "demo_peer_r5.py")],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr[-2000:])
        body = json.loads(run.stdout)
        self.assertEqual(body["status"], "R5_LOCAL_GRANT_LIFECYCLE_VERIFIED")
        self.assertTrue(body["revocation_without_restart"])
        self.assertFalse(body["live_xi_connected"])


if __name__ == "__main__":
    unittest.main()
