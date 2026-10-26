"""R18.2 static console build and live-R18.1 contract parity tests."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'reference'/'python'))
import build_commons_gateway as build
import xi_two_house_r181 as r181

class LabConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='phi-xi-r182-')
        cls.root=Path(cls.tmp.name)/'site'
        cls.report=build.build(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_site_includes_local_only_console(self):
        for file in ('lab.html','lab.css','lab.js','lab-core.js','lab-preview.json','sw.js'):
            self.assertTrue((self.root/file).is_file(),file)
        html=(self.root/'index.html').read_text()
        self.assertIn('href="./lab.html"',html)
        self.assertIn('Six views. One source of truth.',html)
        console=(self.root/'lab.html').read_text()
        self.assertIn('live Xi connection'.upper(),console.upper())
        self.assertIn("connect-src 'self'",console)
        self.assertIn('maximum 16 KiB',console)
        self.assertNotIn('<iframe',console)

    def test_generated_preview_matches_r181_demo_output(self):
        preview=json.loads((self.root/'lab-preview.json').read_text())
        self.assertEqual(preview['schema'],'PhiXi.R18_2_LocalLabPreview.v1')
        self.assertIs(preview['preview_only'],True)
        self.assertEqual(preview['classification'],'illustrative_fixture_not_fresh_run')
        self.assertEqual(preview['witness'],r181.demo())
        self.assertEqual(preview['witness']['physical_hosts'],1)
        self.assertIs(preview['witness']['live_xi_connected'],False)

    def test_offline_worker_allowlists_public_lab_only(self):
        sw=(self.root/'sw.js').read_text()
        for asset in ('./lab.html','./lab.css','./lab.js','./lab-core.js',
                      './lab-preview.json'):
            self.assertIn('"'+asset+'"',sw)
        self.assertIn('if (url.origin !== self.location.origin',sw)
        self.assertNotIn('__VERSION__',sw)
        self.assertNotIn('https://',sw)

    def test_build_cache_id_deterministic(self):
        again=build.build(Path(self.tmp.name)/'second')
        self.assertEqual(again['cache_version'],self.report['cache_version'])
        self.assertEqual((self.root/'lab-preview.json').read_bytes(),
                         (Path(self.tmp.name)/'second'/'lab-preview.json').read_bytes())

if __name__=='__main__':
    unittest.main()
