"""R18.7 source fixtures and static charter bundle never claim operator approval."""
from pathlib import Path
import sys
import tempfile
import unittest
import json

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
sys.path.insert(0,str(ROOT/"reference"/"python"))
import build_commons_gateway as build
import xi_pilot_r18 as r18

class CharterSourceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.t=tempfile.TemporaryDirectory()
  cls.dist=Path(cls.t.name)/"dist"
  cls.report=build.build(cls.dist)
 @classmethod
 def tearDownClass(cls): cls.t.cleanup()
 def test_exact_original_R18_fixture_and_unapproved_preflight_bundled(self):
  fixture=json.loads((self.dist/"handoff"/"synthetic-fixture.json").read_text())
  draft=json.loads((self.dist/"handoff"/"pilot-preflight-draft.json").read_text())
  self.assertEqual(fixture,r18.fixture())
  self.assertEqual(draft,r18.draft())
  self.assertEqual(r18.verify_fixture(fixture)["sha256"],r18.sha(r18.PAYLOAD))
  self.assertEqual(r18.inspect_preflight(draft)["pilot_status"],"BLOCKED_PENDING_INDEPENDENT_PROOF")
  self.assertEqual(len(r18.PAYLOAD),88)
 def test_eighth_site_door_and_offline_allowlist(self):
  html=(self.dist/"index.html").read_text()
  self.assertIn("Eight views. One source of truth.",html)
  self.assertIn('href="./charter.html"',html)
  page=(self.dist/"charter.html").read_text()
  self.assertIn("Human approval from either house",page)
  self.assertIn("connect-src 'self'",page)
  self.assertIn("R18 TWO-HOST: NOT RUN",page)
  worker=(self.dist/"sw.js").read_text()
  for f in ("charter.html","charter.css","charter-core.js","charter.js"):
   self.assertTrue((self.dist/f).is_file(),f)
   self.assertIn('"./'+f+'"',worker)
  self.assertIn('"./handoff/pilot-preflight-draft.json"',worker)
 def test_deterministic_artifacts(self):
  next_root=Path(self.t.name)/"second"
  result=build.build(next_root)
  self.assertEqual(result["cache_version"],self.report["cache_version"])
  for f in ("charter.html","charter.css","charter-core.js","charter.js"):
   self.assertEqual((self.dist/f).read_bytes(),(next_root/f).read_bytes())

if __name__=="__main__": unittest.main()
