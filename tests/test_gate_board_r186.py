"""R18.6 static planning board is deterministic and offline, with no gate promotion."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import build_commons_gateway as builder

class ReadinessBoardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.tmp.name)/"built"
        cls.build=builder.build(cls.root)
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def test_pages_and_offline_allowlist(self):
        for name in ("gates.html","gates.css","gates.js","gates-core.js"):
            self.assertTrue((self.root/name).is_file(),name)
            self.assertIn('"./'+name+'"',(self.root/"sw.js").read_text())
        homepage=(self.root/"index.html").read_text()
        self.assertIn("Seven views. One source of truth.",homepage)
        self.assertIn('href="./gates.html"',homepage)
        board=(self.root/"gates.html").read_text()
        self.assertIn("16 / 16 EXTERNAL GATES OUTSTANDING",board)
        self.assertIn("connect-src 'self'",board)
        self.assertIn("R18 REAL TWO-HOST: NOT RUN",board)
    def test_public_assets_deterministic(self):
        another=Path(self.tmp.name)/"second"
        other=builder.build(another)
        self.assertEqual(other["cache_version"],self.build["cache_version"])
        self.assertEqual((self.root/"gates.js").read_bytes(),(another/"gates.js").read_bytes())
if __name__=="__main__": unittest.main()
