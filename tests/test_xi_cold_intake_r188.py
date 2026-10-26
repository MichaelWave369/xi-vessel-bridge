"""R18.8 cold-intake regression tests. Synthetic ZIPs ONLY: no partner ZIP committed."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import pathlib
import stat
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import xi_cold_intake_r188 as cold


def blob_zip(files: dict[str, bytes], *, symlinks=()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, body in files.items():
            if name in symlinks:
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, body)
            else:
                z.writestr(name, body)
    return buf.getvalue()


def pins(files: dict[str, bytes], role: str, *, sections=None):
    records = {
        name: {"size_bytes": len(body), "sha256": cold.digest(body)}
        for name, body in files.items()
    }
    if role in ("v28", "kernel"):
        result = {"files": records}
        if sections is not None:
            result["sections"] = sections
        return result
    records_list = [
        {"path": name, "bytes": len(body), "sha256": cold.digest(body)}
        for name, body in files.items()
    ]
    return {"records" if role == "architecture" else "files": records_list}


def fixture_bundle(role: str, files: dict[str, bytes], *, sections=None) -> bytes:
    return blob_zip({
        **files,
        cold.MANIFEST_NAMES[role]: json.dumps(
            pins(files, role, sections=sections), sort_keys=True).encode("utf-8")
    })


class ColdIntakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        v28 = fixture_bundle("v28", {"README_OFFLINE.md": b"public synthetic fixture"})
        circuit = blob_zip({"LIVING.md": b"same nested bytes in both bundles"})
        full = fixture_bundle("fullstack", {
            "packages/Plex-v28-shared-bundle.zip": v28,
            "packages/Xi-LivingCircuit-v3.zip": circuit,
            "capsules/QuantumCompute.Spectral.v3.xi": b"synthetic sample only",
        })
        arch = fixture_bundle("architecture", {
            "original-shared-packages/QuantumCompute-v28-shared-bundle.zip": v28,
            "original-shared-packages/20261022-123124-239cf6da-Xi-LivingCircuit-v3.zip": circuit,
            "architecture/spec.md": b"public generic example",
        })
        kernel = fixture_bundle("kernel", {
            "01_Xi_QuantumCompute_FullStack_Kernel/xi_quantum/runtime.py": b"# do not execute\n",
        }, sections={"04_STMC_E47_and_Covariance_Research": "described, absent"})
        self.originals = {"v28": v28, "fullstack": full, "architecture": arch, "kernel": kernel}
        self.paths = {}
        for role, raw in self.originals.items():
            path = self.root / (role + ".zip")
            path.write_bytes(raw)
            self.paths[role] = path

    def tearDown(self):
        self.tmp.cleanup()

    def _replace(self, role, raw):
        self.paths[role].write_bytes(raw)

    def test_all_four_manifests_and_deduplicated_nested_archives(self):
        summary = cold.audit(self.paths)
        self.assertEqual(summary["schema"], "PhiXi.R18_8_ColdIntakeReport.v1")
        self.assertTrue(summary["relationships"]["v28_identical_across_three_locations"])
        self.assertTrue(summary["relationships"]["living_circuit_v3_identical_across_two_locations"])
        self.assertFalse(summary["relationships"]["source_authenticity_verified"])
        self.assertFalse(summary["independent_code_execution"])
        self.assertFalse(summary["nested_archives_extracted"])
        self.assertFalse(summary["redistribution_approval_verified"])
        self.assertEqual(summary["authority"], "none")
        self.assertEqual(summary["r17_external_pilot"], "BLOCKED")
        self.assertEqual(summary["r18_real_two_host_pilot"], "NOT_RUN")
        self.assertIn("DECLARED_SECTION_WITHOUT_FILES", summary["warnings"])
        text = json.dumps(summary)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("README_OFFLINE.md", text)

    def test_source_manifest_tamper_is_refused(self):
        self._replace("v28", blob_zip({
            "README_OFFLINE.md": b"changed content",
            "README_PINS.json": json.dumps(pins(
                {"README_OFFLINE.md": b"old content"}, "v28")).encode(),
        }))
        with self.assertRaisesRegex(cold.IntakeRefused, "manifest"):
            cold.audit(self.paths)

    def test_nested_duplicate_replacement_is_refused(self):
        full = fixture_bundle("fullstack", {
            "packages/Plex-v28-shared-bundle.zip": b"different bytes",
            "packages/Xi-LivingCircuit-v3.zip": blob_zip({"LIVING.md": b"not the same"}),
        })
        self._replace("fullstack", full)
        with self.assertRaises(cold.IntakeRefused):
            cold.audit(self.paths)

    def test_path_traversal_and_case_collision_are_refused(self):
        for bad_files in [
            {"../secret": b"evil"},
            {"/absolute": b"evil"},
            {"C:\\drive\\file": b"evil"},
            {"a/../b": b"evil"},
            {"a": b"one", "A": b"two"},
        ]:
            self._replace("v28", fixture_bundle("v28", bad_files))
            with self.subTest(files=list(bad_files)):
                with self.assertRaises(cold.IntakeRefused):
                    cold.audit(self.paths)

    def test_symbolic_link_is_refused_without_extraction(self):
        self._replace("v28", blob_zip({
            "pointer": b"../../secrets",
            "README_PINS.json": json.dumps(pins(
                {"pointer": b"../../secrets"}, "v28")).encode(),
        }, symlinks=("pointer",)))
        with self.assertRaisesRegex(cold.IntakeRefused, "symbolic"):
            cold.audit(self.paths)
        self.assertEqual(set(self.root.iterdir()), set(self.paths.values()))

    def test_changed_note_is_not_silently_manifest_pinned(self):
        full = fixture_bundle("fullstack", {"packages/Plex-v28-shared-bundle.zip": self.originals["v28"],
                                          "packages/Xi-LivingCircuit-v3.zip": b"not a zip"})
        with zipfile.ZipFile(io.BytesIO(full)) as src:
            files = {n: src.read(n) for n in src.namelist()}
        self._replace("fullstack", blob_zip({**files, "START-HERE.txt": b"unapproved note"}))
        with self.assertRaisesRegex(cold.IntakeRefused, "note"):
            cold.audit(self.paths)

    def test_oversized_advertised_file_rejected(self):
        self._replace("v28", fixture_bundle("v28", {"large.txt": b"a" * (cold.MAX_ENTRY_BYTES + 1)}))
        with self.assertRaises(cold.IntakeRefused):
            cold.audit(self.paths)

    def test_cli_fails_closed_and_does_not_leak_paths(self):
        args = [f"--bundle={role}={self.paths[role]}" for role in cold.ROLES]
        report = self.root / "report.json"
        self.assertEqual(cold.main([*args, "--out", str(report)]), 0)
        self.assertTrue(report.is_file())
        self.assertNotIn(str(self.root), report.read_text())
        self.assertEqual(cold.main(["--bundle=v28=/no/such/archive.zip"]), 2)


if __name__ == "__main__":
    unittest.main()
