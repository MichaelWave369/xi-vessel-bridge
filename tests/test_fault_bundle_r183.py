"""R18.3 static failure lab bundle and public offline-only availability checks."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import build_commons_gateway as gateway

class FaultBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.site=Path(cls.temp.name)/"site"
        cls.report=gateway.build(cls.site)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_site_contains_all_static_public_fault_files(self):
        for asset in ("fault.html","fault.css","fault.js","fault-core.js"):
            self.assertTrue((self.site/asset).is_file(),asset)
        self.assertIn('href="./fault.html"',(self.site/"index.html").read_text())
        self.assertIn('href="./fault.html"',(self.site/"lab.html").read_text())
        self.assertIn("Seven views. One source of truth.",(self.site/"index.html").read_text())

    def test_self_contained_page_cannot_issue_network_calls(self):
        html=(self.site/"fault.html").read_text()
        self.assertIn("connect-src 'none'",html)
        self.assertIn("worker-src 'none'",html)
        self.assertIn("LIVE_XI_CONNECTED=false",html)
        self.assertIn('src="./fault-core.js"',html)
        self.assertIn('src="./fault.js"',html)

    def test_offline_worker_caches_only_known_sandbox_assets(self):
        worker=(self.site/"sw.js").read_text()
        for asset in ("fault.html","fault.css","fault.js","fault-core.js"):
            self.assertIn('"./'+asset+'"',worker)
        self.assertIn('url.origin !== self.location.origin',worker)
        self.assertNotIn("__VERSION__",worker)

    def test_versioned_build_deterministic(self):
        rebuilt=Path(self.temp.name)/"second"
        second=gateway.build(rebuilt)
        self.assertEqual(self.report["cache_version"],second["cache_version"])
        self.assertEqual((self.site/"fault-core.js").read_bytes(),(rebuilt/"fault-core.js").read_bytes())
        self.assertEqual((self.site/"sw.js").read_bytes(),(rebuilt/"sw.js").read_bytes())

if __name__=="__main__":
    unittest.main()
