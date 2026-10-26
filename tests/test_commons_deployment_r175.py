"""R17.5 public HTTPS gateway proof, with local deterministic fake transport."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_commons_gateway as builder
import verify_commons_deployment as verify


class PublicSiteVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.site = Path(cls.tmp.name) / "site"
        cls.report = builder.build(cls.site)
        cls.base = verify.BASE

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def fake_get(self, url):
        verify.validate_base(self.base)
        if not url.startswith(self.base):
            raise verify.NotVerified("unexpected fake host")
        relative = url[len(self.base):] or "index.html"
        return (self.site / relative).read_bytes()

    def test_built_site_passes_public_shape_but_never_live_xi(self):
        result = verify.verify_site(self.base, self.fake_get)
        self.assertEqual(result["verification"], "PUBLIC_STATIC_GATEWAY_VERIFIED")
        self.assertEqual(result["public_url"], verify.BASE)
        self.assertEqual(result["authority"], "none")
        self.assertEqual(result["live_xi_connected"], False)
        self.assertEqual(result["r18_real_two_host_pilot"], "NOT_RUN")
        self.assertEqual(result["checked_public_resources"], 25)
        self.assertEqual(result["r18_6_scope"], "SIXTEEN_OUTSTANDING_DISCUSSION_ONLY_NO_AUTHORITY")
        self.assertEqual(result["r18_5_scope"], "PUBLIC_NONSECRET_ROOM_BRIEFING_NO_EXTERNAL_AUTHORITY")
        self.assertEqual(result["r18_3_scope"], "BROWSER_ONLY_DETERMINISTIC_NO_CRYPTO")
        self.assertEqual(result["lab_scope"], "ILLUSTRATIVE_AND_UNTRUSTED_IMPORTS_ONLY")
        self.assertEqual(len(result["verified_synthetic_packets"]), 4)

    def test_expected_manifest_matches_tested_build_bytes(self):
        expected = hashlib.sha256((self.site / "handoff/manifest.json").read_bytes()).hexdigest()
        result = verify.verify_site(self.base, self.fake_get, expected_manifest=expected)
        self.assertEqual(result["manifest_sha256"], expected)

    def test_wrong_expected_manifest_rejected(self):
        with self.assertRaisesRegex(verify.NotVerified, "differs"):
            verify.verify_site(self.base, self.fake_get, expected_manifest="0" * 64)

    def test_wrong_site_host_path_query_and_http_refused(self):
        for bad in ("http://michaelwave369.github.io/xi-vessel-bridge/",
                    "https://evil.example/xi-vessel-bridge/",
                    "https://michaelwave369.github.io/",
                    verify.BASE + "?token=anything",
                    verify.BASE + "#fake"):
            with self.subTest(url=bad):
                with self.assertRaises(verify.NotVerified):
                    verify.verify_site(bad, self.fake_get)

    def test_mock_attacker_can_not_swap_packet_content(self):
        def tamper(url):
            raw = self.fake_get(url)
            if url.endswith("handoff/synthetic-fixture.json"):
                return raw.replace(b"synthetic_public", b"private_secret")
            return raw
        with self.assertRaisesRegex(verify.NotVerified, "packet"):
            verify.verify_site(self.base, tamper)

    def test_mock_attacker_can_not_promote_registry(self):
        def tamper(url):
            data = self.fake_get(url)
            if url.endswith("capability-registry.json"):
                obj = json.loads(data)
                obj["live_xi_connected"] = True
                return json.dumps(obj).encode()
            return data
        with self.assertRaises(verify.NotVerified):
            verify.verify_site(self.base, tamper)

    def test_fake_landing_page_is_refused(self):
        def bad(url):
            if url == self.base:
                return b"<html><title>404</title></html>"
            return self.fake_get(url)
        with self.assertRaisesRegex(verify.NotVerified, "landing"):
            verify.verify_site(self.base, bad)

    def test_wrong_expected_lab_preview_refused(self):
        with self.assertRaisesRegex(verify.NotVerified, "lab preview differs"):
            verify.verify_site(self.base, self.fake_get, expected_lab_preview="0" * 64)

    def test_tampered_deployed_lab_preview_refused(self):
        def tamper(url):
            data = self.fake_get(url)
            if url.endswith("/lab-preview.json"):
                obj = json.loads(data)
                obj["witness"]["live_xi_connected"] = True
                return json.dumps(obj).encode()
            return data
        with self.assertRaisesRegex(verify.NotVerified, "lab preview"):
            verify.verify_site(self.base, tamper)

    def test_unexpected_redirect_or_origin_rejected_before_request(self):
        with self.assertRaises(verify.NotVerified):
            verify.fetch_public("https://attacker.invalid/xi-vessel-bridge/")

    def test_missing_public_asset_refused(self):
        def missing(url):
            if url.endswith("/sw.js"):
                raise OSError("404")
            return self.fake_get(url)
        with self.assertRaises(OSError):
            verify.verify_site(self.base, missing)


if __name__ == "__main__":
    unittest.main()
