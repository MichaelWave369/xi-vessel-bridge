"""R17.3 static publishing, evidence integrity and offline-cache tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "reference" / "python"))
import build_commons_gateway as gateway
import xi_capability_r171 as regtool
import xi_pilot_r18 as pilot


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "site"
        cls.report = gateway.build(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_public_gateway_built_with_no_remote_claim(self):
        self.assertEqual(self.report["status"], "PUBLIC_STATIC_GATEWAY_BUILT")
        self.assertFalse(self.report["live_xi_connected"])
        self.assertEqual(self.report["r18_two_host_status"], "NOT_RUN")
        self.assertEqual(self.report["public_packet_files"], 4)

    def test_expected_html_views_and_relative_links(self):
        for path in ("index.html", "roadmap.html", "intake.html",
                     "capabilities.html", "commons.css", "commons.js"):
            self.assertTrue((self.root / path).is_file(), path)
        html = (self.root / "index.html").read_text(encoding="utf-8")
        for path in ('href="./roadmap.html"', 'href="./capabilities.html"',
                     'href="./intake.html"', 'href="./handoff/manifest.json"'):
            self.assertIn(path, html)
        self.assertIn("NOT ESTABLISHED", html)
        self.assertIn("Content-Security-Policy", html)

    def test_handoff_manifest_matches_exact_bytes(self):
        info = json.loads((self.root / "handoff" / "manifest.json").read_text())
        self.assertEqual(info["schema"], gateway.SCHEMA)
        self.assertEqual(info["authority"], "none")
        self.assertFalse(info["live_xi_connected"])
        self.assertEqual(len(info["files"]), 4)
        for entry in info["files"]:
            data = (self.root / "handoff" / entry["name"]).read_bytes()
            self.assertEqual(entry["size_bytes"], len(data))
            self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertLessEqual(len(data), 32768)

    def test_request_registry_binding(self):
        reg = regtool.read_json(self.root / "capability-registry.json")
        request = json.loads((self.root / "handoff" / "request.json").read_text())
        self.assertEqual(request["registry_sha256"], regtool.document_hash(reg))
        self.assertFalse(request["authorization_from_response"])
        self.assertEqual(len(request["slots"]), 13)

    def test_synthetic_fixture_verified(self):
        item = json.loads((self.root / "handoff" / "synthetic-fixture.json").read_text())
        self.assertEqual(pilot.verify_fixture(item)["status"], "OFFLINE_SYNTHETIC_FIXTURE_VERIFIED")

    def test_preflight_and_transcript_not_promoted(self):
        preflight = json.loads((self.root / "handoff" / "pilot-preflight-draft.json").read_text())
        transcript = json.loads((self.root / "handoff" / "transcript-template.json").read_text())
        self.assertEqual(pilot.inspect_preflight(preflight)["pilot_status"],
                         "BLOCKED_PENDING_INDEPENDENT_PROOF")
        self.assertEqual(pilot.inspect_transcript(transcript)["status"], "NOT_RUN")

    def test_offline_allowlist_covers_all_site_files_and_no_remote_origins(self):
        script = (self.root / "sw.js").read_text()
        self.assertNotIn("__VERSION__", script)
        self.assertNotIn("https://", script)
        self.assertIn('if (url.origin !== self.location.origin', script)
        self.assertIn('req.method !== "GET"', script)
        self.assertIn('"./handoff/manifest.json"', script)
        self.assertIn('"./intake-core.js"', script)
        self.assertIn('"./roadmap.html"', script)
        self.assertIn('await cache.addAll', script)

    def test_build_cache_version_stable(self):
        next_root = self.root.parent / "second"
        repeat = gateway.build(next_root)
        self.assertEqual(repeat["cache_version"], self.report["cache_version"])
        self.assertEqual((next_root / "sw.js").read_bytes(), (self.root / "sw.js").read_bytes())
        self.assertEqual((next_root / "handoff" / "manifest.json").read_bytes(),
                         (self.root / "handoff" / "manifest.json").read_bytes())

    def test_handoff_html_does_not_claim_partner_approval(self):
        html = (self.root / "index.html").read_text()
        self.assertIn("No system has to surrender authority", html)
        self.assertIn("Two houses.", html)
        self.assertIn('rel="noopener noreferrer"', html)

    def test_no_undocumented_static_external_scripts(self):
        html = (self.root / "index.html").read_text()
        tags = re.findall(r'<script\b[^>]*src="([^"]+)"', html)
        self.assertEqual(tags, ["./commons.js"])
        self.assertTrue(all(not x.startswith(("https://", "http://")) for x in tags))


if __name__ == "__main__":
    unittest.main()
