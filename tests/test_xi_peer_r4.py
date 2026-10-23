"""R4 acceptance: separate OS processes, loopback fence, no live Xi keys."""
from __future__ import annotations

import copy
import http.client
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
from demo_peer_r4 import fixture_profiles, start_fixture_server
from xi_peer_r3 import CrossingError, LocalKeys, make_offer, seal
from xi_peer_r4_http import (
    PATH, exchange, post_loopback, read_fixture_profile, validate_loopback_url,
)

STAGE = "r4-local-test-room"


class R4LoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="xi-r4-tests-")
        cls.root = Path(cls.temp.name)
        phi_file, xi_file = fixture_profiles(cls.root)
        cls.phi = read_fixture_profile(str(phi_file))
        cls.xi = read_fixture_profile(str(xi_file))
        cls.proc, cls.port = start_fixture_server(xi_file, cls.root, stage=STAGE)
        cls.url = f"http://127.0.0.1:{cls.port}{PATH}"
        cls.state_dir = cls.root / "server-state"
        cls.offer = make_offer(
            "⟨ Ξ ⋈ Φ ⟩",
            {"node": "test", "members": ["phi-fixture", "xi-fixture"]},
            {"author": "phi-fixture", "source": "offline-suite",
             "version": "1", "intended_use": "R4 test"})

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
            cls.proc.communicate(timeout=5)
        cls.temp.cleanup()

    @classmethod
    def frame(cls, **kwargs):
        settings = {
            "sender": cls.phi.local_id, "recipient": cls.phi.peer_id,
            "stage": STAGE, "sender_keys": cls.phi.keys, "recipient_public": cls.phi.peer,
        }
        settings.update(kwargs)
        return seal(cls.offer, **settings)

    def test_full_sealed_client_server_roundtrip(self):
        response = exchange(self.phi, STAGE, self.url, self.offer)
        self.assertEqual(response["status"], "R4_TWO_PROCESS_FIXTURE_VERIFIED")
        self.assertTrue(response["receipt_matches_offer"])
        self.assertFalse(response["live_xi_connected"])

    def test_transport_never_returns_plaintext_capsule(self):
        frame = self.frame()
        status, body = post_loopback(self.url, frame)
        self.assertEqual(status, 200)
        self.assertNotIn(self.offer["xi_text"], json.dumps(body, ensure_ascii=False))
        self.assertEqual(set(body), {"receipt_frame", "mode"})
        self.assertFalse("payload" in body)

    def test_replay_exact_and_changed_frame_rejected(self):
        frame = self.frame()
        self.assertEqual(post_loopback(self.url, frame)[0], 200)
        status, body = post_loopback(self.url, frame)
        self.assertEqual((status, body["reason"]), (409, "replay_rejected"))
        changed = self.frame(request_id=frame["request_id"])
        status, body = post_loopback(self.url, changed)
        self.assertEqual((status, body["reason"]), (409, "request_id_conflict"))

    def test_unknown_identity_and_bad_signature_refused(self):
        attacker = LocalKeys.fresh_fixture()
        frame = self.frame(sender_keys=attacker)
        status, result = post_loopback(self.url, frame)
        self.assertEqual((status, result["reason"]), (403, "invalid_signature"))
        frame = self.frame(sender="untrusted-fixture")
        status, result = post_loopback(self.url, frame)
        self.assertEqual((status, result["reason"]), (403, "untrusted_sender"))

    def test_wrong_scope_and_tampering_refused(self):
        frame = self.frame(stage="wrong-stage")
        status, result = post_loopback(self.url, frame)
        self.assertEqual((status, result["reason"]), (403, "scope_denied"))
        frame = self.frame()
        frame["request_id"] = "00000000-0000-4000-8000-000000000000"
        status, result = post_loopback(self.url, frame)
        self.assertEqual((status, result["reason"]), (403, "invalid_signature"))

    def test_operator_pause_blocks_before_processing(self):
        marker = self.state_dir / "PAUSED"
        marker.touch()
        try:
            status, result = post_loopback(self.url, self.frame())
            self.assertEqual((status, result["reason"]), (503, "bridge_paused"))
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", "/healthz")
            response = conn.getresponse()
            health = json.loads(response.read())
            conn.close()
            self.assertTrue(health["paused"])
            self.assertFalse(health["live_xi_connected"])
        finally:
            marker.unlink()
        self.assertEqual(post_loopback(self.url, self.frame())[0], 200)

    def test_undeclared_endpoint_is_not_a_real_xi_api(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("POST", "/api/xi/v1/inference/generate", "{}", {
                "Content-Type": "application/json"})
            response = conn.getresponse()
            self.assertEqual(response.status, 404)
            response.read()
            conn.request("GET", "/unexpected")
            response = conn.getresponse()
            self.assertEqual(response.status, 404)
            response.read()
        finally:
            conn.close()

    def test_rejects_malformed_json_and_missing_length(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("POST", PATH, "{", {"Content-Type": "application/json"})
            response = conn.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            conn.putrequest("POST", PATH)
            conn.putheader("Content-Type", "application/json")
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
        finally:
            conn.close()

    def test_client_refuses_external_and_redirect_destinations(self):
        for url in [
            "https://room.xi-field.com/v1/fixture/capsule",
            "http://example.com/v1/fixture/capsule",
            "http://localhost:8800/v1/fixture/capsule",
            "http://127.0.0.1:8800/other",
            "http://127.0.0.1:8800/v1/fixture/capsule?redirect=1",
            "http://u:p@127.0.0.1:8800/v1/fixture/capsule",
        ]:
            with self.subTest(url=url), self.assertRaises(CrossingError):
                validate_loopback_url(url)
        self.assertEqual(validate_loopback_url(self.url), self.url)

    def test_insecure_or_symlink_profile_fails_closed(self):
        private = self.root / "insecure.private.json"
        original = self.root / "xi-fixture.private.json"
        private.write_bytes(original.read_bytes())
        if os.name == "posix":
            private.chmod(0o644)
            with self.assertRaises(CrossingError):
                read_fixture_profile(str(private))
        link = self.root / "linked.private.json"
        try:
            link.symlink_to(original)
        except (OSError, NotImplementedError):
            pass
        else:
            if hasattr(os, "O_NOFOLLOW"):
                with self.assertRaises(CrossingError):
                    read_fixture_profile(str(link))

    def test_independent_subprocess_demo(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "reference" / "python" / "demo_peer_r4.py")],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr[-1000:])
        summary = json.loads(completed.stdout)
        self.assertEqual(summary["status"], "R4_TWO_PROCESS_FIXTURE_VERIFIED")
        self.assertFalse(summary["live_xi_connected"])


if __name__ == "__main__":
    unittest.main()
