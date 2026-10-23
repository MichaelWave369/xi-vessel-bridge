"""R6 negative controls: persistent tombstones and immutable grant ID pinning."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from xi_peer_r3 import CrossingError
from xi_peer_r5_policy import atomic_write_fixture_grant, fixture_grant
from xi_peer_r6_ledger import (
    DurableGrantLedger, MonotonicGrantGate, immutable_grant_digest,
    revoke_fixture_grant,
)

NOW = 1797000000
STAGE = "r6-synthetic-fixture"


class R6LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="r6-tests-")
        self.root = Path(self.temp.name)
        self.policy = str(self.root / "operator.json")
        self.path = str(self.root / "operator.sqlite3")
        self.grant = fixture_grant(sender="phi-fixture", recipient="xi-fixture", stage=STAGE,
                                   not_before=NOW-10, expires_at=NOW+120)
        atomic_write_fixture_grant(self.policy, self.grant)
        self.gate = MonotonicGrantGate(self.policy, self.path, clock=lambda: NOW)

    def tearDown(self):
        self.gate.close()
        self.temp.cleanup()

    def authorize(self):
        self.gate("phi-fixture", "xi-fixture", STAGE, "capsule.offer", NOW)

    def assert_refused(self, code):
        with self.assertRaises(CrossingError) as caught:
            self.authorize()
        self.assertEqual(str(caught.exception), code)

    def test_first_scope_admission_is_pinned(self):
        self.authorize()
        row = self.gate.ledger.db.execute("SELECT immutable_sha256,state FROM grant_pins").fetchone()
        self.assertEqual(row, (immutable_grant_digest(self.grant), "active"))
        self.authorize()

    def test_mutated_expiry_same_grant_id_denied(self):
        self.authorize()
        altered = {**self.grant, "expires_at": NOW+180}
        atomic_write_fixture_grant(self.policy, altered)
        self.assert_refused("grant_mutation_denied")
        atomic_write_fixture_grant(self.policy, self.grant)
        self.authorize()

    def test_mutated_peer_or_room_same_grant_id_denied(self):
        self.authorize()
        for change in ({"sender":"other-fixture"}, {"stage":"another-fixture-stage"},
                       {"recipient":"other-fixture"}):
            with self.subTest(change=change):
                atomic_write_fixture_grant(self.policy, {**self.grant, **change})
                self.assert_refused("grant_scope_denied")
        atomic_write_fixture_grant(self.policy, self.grant)
        self.authorize()

    def test_durable_revocation_resists_old_grant_restore(self):
        self.authorize()
        result = revoke_fixture_grant(self.policy, self.path, now=NOW)
        self.assertEqual(result["status"], "R6_FIXTURE_GRANT_REVOKED")
        atomic_write_fixture_grant(self.policy, self.grant)
        self.assert_refused("grant_revoked")
        self.assertEqual(self.gate.ledger.db.execute(
            "SELECT state FROM grant_pins").fetchone()[0], "revoked")

    def test_revocation_survives_connection_restart(self):
        self.authorize()
        revoke_fixture_grant(self.policy, self.path, now=NOW)
        atomic_write_fixture_grant(self.policy, self.grant)
        self.gate.close()
        self.gate = MonotonicGrantGate(self.policy, self.path, clock=lambda: NOW)
        self.assert_refused("grant_revoked")

    def test_revoked_policy_without_cli_creates_tombstone(self):
        revoked = {**self.grant, "revoked": True}
        atomic_write_fixture_grant(self.policy, revoked)
        self.assert_refused("grant_revoked")
        atomic_write_fixture_grant(self.policy, self.grant)
        self.assert_refused("grant_revoked")

    def test_revoke_never_rolled_back_if_json_replace_fails(self):
        self.authorize()
        with patch("xi_peer_r6_ledger.atomic_write_fixture_grant", side_effect=OSError("fixture IO failure")):
            with self.assertRaises(OSError):
                revoke_fixture_grant(self.policy, self.path, now=NOW)
        # Old JSON is still present, but durable tombstone must deny it.
        self.assert_refused("grant_revoked")

    def test_expired_and_wrong_scope_grants_not_pinned_as_admitted(self):
        atomic_write_fixture_grant(self.policy, {**self.grant, "not_before":NOW+1})
        self.assert_refused("grant_expired_or_not_yet_valid")
        self.assertEqual(self.gate.ledger.db.execute(
            "SELECT count(*) FROM grant_pins").fetchone()[0], 0)
        atomic_write_fixture_grant(self.policy, {**self.grant, "sender":"other-fixture"})
        self.assert_refused("grant_scope_denied")
        self.assertEqual(self.gate.ledger.db.execute(
            "SELECT count(*) FROM grant_pins").fetchone()[0], 0)

    def test_new_grant_id_requires_a_new_explicit_policy(self):
        self.authorize()
        revoke_fixture_grant(self.policy, self.path, now=NOW)
        new_grant = fixture_grant(sender="phi-fixture", recipient="xi-fixture",
                                  stage=STAGE, not_before=NOW-10, expires_at=NOW+60)
        atomic_write_fixture_grant(self.policy, new_grant)
        self.authorize()
        states = self.gate.ledger.db.execute(
            "SELECT grant_id,state FROM grant_pins").fetchall()
        self.assertEqual(set(s for _, s in states), {"active", "revoked"})
        self.assertEqual(len(states), 2)

    def test_revoke_unknown_grant_id_before_any_use(self):
        revoke_fixture_grant(self.policy, self.path, now=NOW)
        self.assert_refused("grant_revoked")
        self.assertEqual(self.gate.ledger.db.execute(
            "SELECT state FROM grant_pins").fetchone()[0], "revoked")

    def test_replay_changed_same_grant_id_even_when_revoked_denied(self):
        self.authorize()
        revoke_fixture_grant(self.policy, self.path, now=NOW)
        altered = {**self.grant, "not_before":NOW-11}
        atomic_write_fixture_grant(self.policy, altered)
        self.assert_refused("grant_mutation_denied")

    def test_subprocess_peer_crossing_and_restart(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "reference" / "python" / "demo_peer_r6.py")],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr[-1000:])
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "R6_MONOTONIC_REVOCATION_VERIFIED")
        self.assertTrue(report["old_grant_file_rollback_denied"])
        self.assertTrue(report["server_restart_keeps_revocation"])
        self.assertFalse(report["live_xi_connected"])


if __name__ == "__main__":
    unittest.main()
