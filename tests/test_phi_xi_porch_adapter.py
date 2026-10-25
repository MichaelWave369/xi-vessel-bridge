"""Negative-control tests for the offline PhiOS/Xi porch adapter (no network)."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reference" / "python"))
import phi_xi_porch_adapter as bridge

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64(data):
    return base64.b64encode(data).decode("ascii")


def signed(key, kind="announce", **fields):
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    msg = {"schema": bridge.RELAY_SCHEMA, "kind": kind, "id": "test-id",
           "from": "ed25519:" + b64(pub), "ts": 1_700_000_000, **fields}
    msg["sig"] = b64(key.sign(bridge.canonical(msg)))
    return msg


def tar_fixture(path, tamper=False, extra=False, traversal=False):
    cargo = b"read-only sample"
    pins = {"files": {"item.txt": {"sha256": hashlib.sha256(cargo).hexdigest(),
                                   "size_bytes": len(cargo)}}}
    with tarfile.open(path, "w:gz") as tar:
        for name, data in [
            ("README_PINS.json", json.dumps(pins).encode()),
            ("item.txt", (b"tampered" if tamper else cargo)),
        ] + ([("extra.txt", b"bad")] if extra else []) + ([("../escape", b"bad")] if traversal else []):
            meta = tarfile.TarInfo(name)
            meta.size = len(data)
            tar.addfile(meta, io.BytesIO(data))


class PorchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        self.sha = bridge.digest(b"payload")
        self.pins = {signed(self.key, sha256=self.sha, size=7)["from"]}

    def test_inventory_is_deterministic_and_read_only(self):
        work = self.root / "gitporch"
        work.mkdir()
        (work / "b.txt").write_text("B")
        (work / "a.txt").write_text("A")
        first = bridge.inventory(work)
        self.assertEqual(first, bridge.inventory(work))
        self.assertEqual(first["file_count"], 2)
        self.assertEqual([r["path"] for r in first["entries"]], ["a.txt", "b.txt"])
        self.assertFalse(first["live_xi_connected"])

    def test_inventory_refuses_symlinks(self):
        work = self.root / "gitporch"
        work.mkdir()
        target = self.root / "secret"
        target.write_text("hidden")
        try:
            (work / "alias").symlink_to(target)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(bridge.Refused):
            bridge.inventory(work)

    def test_inventory_rejects_oversized_file(self):
        work = self.root / "gitporch"
        work.mkdir()
        (work / "large.bin").write_bytes(b"x" * (bridge.MAX_FILE + 1))
        with self.assertRaises(bridge.Refused):
            bridge.inventory(work)

    def test_audit_manifest_good(self):
        archive = self.root / "v9-fixture.tar.gz"
        tar_fixture(archive)
        result = bridge.audit_bundle(archive)
        self.assertEqual(result["verified_files"], 1)
        self.assertFalse(result["executed"])
        self.assertEqual(result["authority"], "self-declared-hashes-only")

    def test_audit_rejects_content_tamper(self):
        archive = self.root / "bad.tar.gz"
        tar_fixture(archive, tamper=True)
        with self.assertRaises(bridge.Refused):
            bridge.audit_bundle(archive)

    def test_audit_rejects_extra_files(self):
        archive = self.root / "extra.tar.gz"
        tar_fixture(archive, extra=True)
        with self.assertRaises(bridge.Refused):
            bridge.audit_bundle(archive)

    def test_audit_rejects_traversal(self):
        archive = self.root / "traversal.tar.gz"
        tar_fixture(archive, traversal=True)
        with self.assertRaises(bridge.Refused):
            bridge.audit_bundle(archive)

    def test_announce_passes_only_with_pin(self):
        msg = signed(self.key, sha256=self.sha, size=7, note="gitporch")
        result = bridge.inspect_relay([msg], self.pins, now=1_700_000_000)
        self.assertEqual(result["messages_verified"], 1)
        self.assertEqual(result["authority"], "none")

    def test_unpinned_key_rejected(self):
        msg = signed(self.other, sha256=self.sha, size=7)
        with self.assertRaises(bridge.Refused):
            bridge.inspect_relay([msg], self.pins, now=1_700_000_000)

    def test_signed_payload_tamper_rejected(self):
        msg = signed(self.key, sha256=self.sha, size=7)
        msg["size"] = 8
        with self.assertRaises(bridge.Refused):
            bridge.inspect_relay([msg], self.pins, now=1_700_000_000)

    def test_stale_message_rejected(self):
        msg = signed(self.key, sha256=self.sha, size=7)
        with self.assertRaises(bridge.Refused):
            bridge.inspect_relay([msg], self.pins, now=1_700_001_000)

    def test_signed_request_always_refused(self):
        msg = signed(self.key, kind="request", sha256=self.sha)
        with self.assertRaises(bridge.Refused):
            bridge.inspect_relay([msg], self.pins, now=1_700_000_000)

    def test_valid_inline_delivery(self):
        data = b"payload"
        msg = signed(self.key, kind="deliver", sha256=bridge.digest(data),
                     size=len(data), via="inline", data=b64(data))
        self.assertEqual(bridge.inspect_relay([msg], self.pins, now=1_700_000_000)
                         ["messages"][0]["content"], "verified")

    def test_pointer_only_delivery_refused(self):
        msg = signed(self.key, kind="deliver", sha256=self.sha, size=7, via="lightbridge")
        with self.assertRaises(bridge.Refused):
            bridge.inspect_relay([msg], self.pins, now=1_700_000_000)

    def test_replayed_id_in_batch_rejected(self):
        msg = signed(self.key, sha256=self.sha, size=7)
        with self.assertRaises(bridge.Refused):
            bridge.inspect_relay([msg, msg], self.pins, now=1_700_000_000)

    def test_false_receipt_is_rejected(self):
        msg = signed(self.key, kind="receipt", sha256=self.sha,
                     received_sha256=bridge.digest(b"different"), matched=True, in_reply_to="request-one")
        with self.assertRaises(bridge.Refused):
            bridge.inspect_relay([msg], self.pins, now=1_700_000_000)

    def test_read_pins_format(self):
        peer = next(iter(self.pins))
        path = self.root / "pins.json"
        path.write_text(json.dumps({"peers": [{"ed25519": peer, "name": "offline-test"}]}))
        self.assertEqual(bridge.read_pins(path), self.pins)

    def test_not_xi_bridge_envelope(self):
        self.assertNotEqual(bridge.RELAY_SCHEMA, "xi.exchange.v1")


if __name__ == "__main__":
    unittest.main()
