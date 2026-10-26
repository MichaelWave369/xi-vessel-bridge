"""R18.5 Commons re-entry page is public, static, deterministic and offline allowlisted."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import build_commons_gateway as builder

class RoomReentryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.site=Path(cls.temp.name)/"dist"
        cls.build=builder.build(cls.site)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def test_published_static_room_and_six_doorways(self):
        for name in ("room.html","room.js","room.css"):
            self.assertTrue((self.site/name).is_file())
        index=(self.site/"index.html").read_text()
        self.assertIn('href="./room.html"',index)
        self.assertIn("Six views. One source of truth.",index)
        page=(self.site/"room.html").read_text()
        self.assertIn("connect-src 'none'",page)
        self.assertIn("REAL TWO-HOST TEST NOT RUN",page)
        self.assertIn("All 16 external readiness gates remain unresolved",page)
    def test_offline_worker_precaches_only_reviewed_room_assets(self):
        worker=(self.site/"sw.js").read_text()
        for asset in ("room.html","room.js","room.css"):
            self.assertIn('"./'+asset+'"',worker)
        self.assertIn("url.origin !== self.location.origin",worker)
        self.assertNotIn("__VERSION__",worker)
    def test_deterministic_versioning(self):
        out=Path(self.temp.name)/"dist-again"
        other=builder.build(out)
        self.assertEqual(self.build["cache_version"],other["cache_version"])
        self.assertEqual((self.site/"room.html").read_bytes(),(out/"room.html").read_bytes())

if __name__=="__main__": unittest.main()
