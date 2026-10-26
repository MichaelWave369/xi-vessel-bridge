#!/usr/bin/env python3
"""R18.8 Xi→Phi cold intake: untrusted ZIP validation WITHOUT extraction/execution.

Standard library only. The partner's archives stay on the operator's computer;
never push them, executable contents, secrets, or private manifest text to GitHub.
This verifies ZIP integrity and self-reported manifest parity, NOT sender identity,
license, permission to redistribute, algorithm correctness, or independent Xi consent.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import re
import stat
import sys
import unicodedata
import zipfile
from collections import Counter

ROLES = ("v28", "fullstack", "architecture", "kernel")
MANIFEST_NAMES = {
    "v28": "README_PINS.json",
    "fullstack": "MANIFEST.json",
    "architecture": "MANIFEST.json",
    "kernel": "MANIFEST_PINS.json",
}
NESTED = {
    "fullstack": {
        "v28": "packages/Plex-v28-shared-bundle.zip",
        "v3": "packages/Xi-LivingCircuit-v3.zip",
    },
    "architecture": {
        "v28": "original-shared-packages/QuantumCompute-v28-shared-bundle.zip",
        "v3": "original-shared-packages/20261022-123124-239cf6da-Xi-LivingCircuit-v3.zip",
    },
}
MAX_ENTRIES = 500
MAX_ENTRY_BYTES = 24 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED = 48 * 1024 * 1024
MAX_NESTED_TOTAL = 64 * 1024 * 1024
MAX_NESTING_DEPTH = 1
MAX_RATIO = 5000
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

class IntakeRefused(Exception):
    """Fail closed for unsafe archives or mismatched source pins."""


def insist(condition: bool, message: str) -> None:
    if not condition:
        raise IntakeRefused(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    insist(isinstance(name, str) and len(name) <= 4096, "unsafe member name")
    insist("\x00" not in name and "\\" not in name and not name.startswith("/"),
           "unsafe absolute or escaped member name")
    insist(not re.match(r"^[A-Za-z]:", name), "drive-prefixed member name")
    insist(all(part not in ("", ".", "..") for part in name.rstrip("/").split("/")),
           "empty or traversing member path")
    insist(unicodedata.normalize("NFC", name) == name, "ambiguous Unicode archive path")
    return name


def _read_members(z: zipfile.ZipFile, *, depth: int, budget: int) -> tuple[dict, dict, list]:
    infos = z.infolist()
    insist(len(infos) <= MAX_ENTRIES, "archive has too many members")
    total_claimed = sum(i.file_size for i in infos)
    insist(total_claimed <= budget, "archive decompression exceeds cap")
    members = {}
    nested = {}
    warnings = []
    collision = set()
    for info in infos:
        name = _safe_name(info.filename)
        folded = name.casefold()
        insist(folded not in collision, "duplicate or case-colliding archive entry")
        collision.add(folded)
        if info.is_dir():
            continue
        mode = info.external_attr >> 16
        insist(not stat.S_ISLNK(mode), "archive contains symbolic link")
        insist(not (info.flag_bits & 0x1), "encrypted archive entry refused")
        insist(info.file_size <= MAX_ENTRY_BYTES, "member uncompressed size exceeds cap")
        insist(info.compress_size > 0 or info.file_size == 0, "invalid compressed size")
        if info.compress_size:
            insist(info.file_size / info.compress_size <= MAX_RATIO,
                   "excessive decompression ratio")
        count = 0
        chunks = []
        sha = hashlib.sha256()
        # Using z.open verifies CRC when fully read. No files are extracted.
        try:
            with z.open(info, "r") as handle:
                while True:
                    chunk = handle.read(1024 * 256)
                    if not chunk:
                        break
                    count += len(chunk)
                    insist(count <= info.file_size and count <= MAX_ENTRY_BYTES,
                           "entry decompressed beyond advertised bounds")
                    sha.update(chunk)
                    if name.endswith(".zip") or name in ("README_PINS.json", "MANIFEST.json", "MANIFEST_PINS.json"):
                        chunks.append(chunk)
        except (zipfile.BadZipFile, EOFError, RuntimeError, OSError) as exc:
            raise IntakeRefused("archive member CRC or decompression failure") from exc
        insist(count == info.file_size, "decompressed size mismatch")
        members[name] = {"size_bytes": count, "sha256": sha.hexdigest()}
        if name.endswith(".zip"):
            raw = b"".join(chunks)
            if not zipfile.is_zipfile(io.BytesIO(raw)):
                warnings.append("NON_ZIP_PLACEHOLDER_AT_ZIP_PATH")
            else:
                insist(depth < MAX_NESTING_DEPTH, "nested archive depth exceeds cap")
                try:
                    with zipfile.ZipFile(io.BytesIO(raw)) as inner:
                        inner_info = inner.infolist()
                        insist(len(inner_info) <= MAX_ENTRIES,
                               "nested archive has too many entries")
                        insist(sum(i.file_size for i in inner_info) <= MAX_NESTED_TOTAL,
                               "nested archive exceeds decompression cap")
                        # Validate metadata safety; no extraction or execution.
                        seen = set()
                        for item in inner_info:
                            n = _safe_name(item.filename)
                            insist(n.casefold() not in seen, "duplicate nested archive path")
                            seen.add(n.casefold())
                            insist(not stat.S_ISLNK(item.external_attr >> 16),
                                   "nested archive symlink")
                            insist(not item.flag_bits & 0x1, "encrypted nested member")
                            insist(item.file_size <= MAX_ENTRY_BYTES, "oversized nested member")
                            insist(item.compress_size > 0 or item.file_size == 0,
                                   "invalid nested member compression")
                            if item.compress_size:
                                insist(item.file_size / item.compress_size <= MAX_RATIO,
                                       "nested decompression ratio exceeded")
                        # Do not decompress/extract nested archives here.
                except (zipfile.BadZipFile, EOFError, RuntimeError) as exc:
                    raise IntakeRefused("invalid nested archive") from exc
                nested[name] = sha.hexdigest()
    return members, nested, warnings


def _read_manifest(z: zipfile.ZipFile, role: str) -> dict:
    name = MANIFEST_NAMES[role]
    try:
        data = z.read(name)
    except KeyError as exc:
        raise IntakeRefused("required manifest absent") from exc
    insist(len(data) <= 2 * 1024 * 1024, "oversized manifest")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeRefused("invalid JSON manifest") from exc
    insist(isinstance(doc, dict), "manifest must be object")
    return doc


def _pins(doc: dict, role: str) -> dict:
    if role in ("v28", "kernel"):
        records = doc.get("files")
        insist(isinstance(records, dict), "manifest files object missing")
        out = {}
        for name, record in records.items():
            insist(isinstance(record, dict), "invalid manifest file record")
            out[_safe_name(name)] = (record.get("size_bytes"), record.get("sha256"))
        return out
    field = "files" if role == "fullstack" else "records"
    records = doc.get(field)
    insist(isinstance(records, list), "manifest files/records missing")
    out = {}
    for record in records:
        insist(isinstance(record, dict), "invalid manifest record")
        name = _safe_name(record.get("path"))
        insist(name not in out, "duplicate manifest pin")
        out[name] = (record.get("bytes"), record.get("sha256"))
    return out


def audit_archive(role: str, path: pathlib.Path) -> dict:
    insist(role in ROLES, "unknown bundle role")
    try:
        raw = path.read_bytes()
    except (OSError, ValueError) as exc:
        raise IntakeRefused("local bundle missing or unreadable") from exc
    insist(0 < len(raw) <= 48 * 1024 * 1024, "outer archive size outside limits")
    insist(zipfile.is_zipfile(io.BytesIO(raw)), "outer bundle is not a ZIP")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            members, nested, warnings = _read_members(
                z, depth=0, budget=MAX_ARCHIVE_UNCOMPRESSED)
            manifest = _read_manifest(z, role)
            expected = _pins(manifest, role)
    except (zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise IntakeRefused("invalid ZIP structure") from exc
    manifest_name = MANIFEST_NAMES[role]
    extra = set(members) - {manifest_name} - set(expected)
    if role == "fullstack" and extra == {"START-HERE.txt"}:
        note = members["START-HERE.txt"]
        insist(note == {
            "size_bytes": 1445,
            "sha256": "251053537f9e9a6fd5a4719ffccab3477f6dc3a9ea607417c7dfaac72eb86078",
        }, "unmanifested START-HERE note differs from reviewed handoff")
        warnings.append("START_HERE_NOTE_NOT_IN_MANIFEST")
    else:
        insist(not extra, "unmanifested extra member")
    insist(set(expected) <= set(members) - {manifest_name},
           "manifest lists absent members")
    for name, (size, sha) in expected.items():
        insist(type(size) is int and size >= 0 and
               isinstance(sha, str) and SHA_RE.fullmatch(sha) is not None,
               "invalid manifest hash or byte count")
        insist(members[name]["size_bytes"] == size and
               members[name]["sha256"] == sha,
               "file bytes differ from attached manifest pins")
    if role == "kernel":
        sections = manifest.get("sections")
        if isinstance(sections, dict):
            absent = [n for n in sections if not any(p.startswith(n + "/") for p in members)]
            if absent:
                warnings.append("DECLARED_SECTION_WITHOUT_FILES")
    return {
        "role": role,
        "sha256": digest(raw),
        "archive_bytes": len(raw),
        "member_count": len(members),
        "manifest_entries_checked": len(expected),
        "manifest_self_consistent": True,
        "nested_archives_count": len(nested),
        "nested_hashes": nested,  # kept in memory; omitted from public report
        "warnings": sorted(set(warnings)),
    }


def audit(paths: dict[str, pathlib.Path]) -> dict:
    insist(set(paths) == set(ROLES), "exactly four independently supplied bundles required")
    found = {role: audit_archive(role, pathlib.Path(paths[role])) for role in ROLES}
    fullstack = found["fullstack"]["nested_hashes"]
    architecture = found["architecture"]["nested_hashes"]
    insist(fullstack.get(NESTED["fullstack"]["v28"]) == found["v28"]["sha256"],
           "fullstack's v28 archive is not the original bundle")
    insist(architecture.get(NESTED["architecture"]["v28"]) == found["v28"]["sha256"],
           "architecture's v28 archive differs from the original")
    insist(fullstack.get(NESTED["fullstack"]["v3"]) ==
           architecture.get(NESTED["architecture"]["v3"]),
           "LivingCircuit v3 copies are not byte-identical")
    warnings = sorted(set(w for info in found.values() for w in info["warnings"]))
    report = {
        "schema": "PhiXi.R18_8_ColdIntakeReport.v1",
        "classification": "LOCAL_UNTRUSTED_PARTNER_ARCHIVE_AUDIT",
        "status": "AUDIT_COMPLETE_WITH_WARNINGS" if warnings else "AUDIT_COMPLETE",
        "archives": [
            {k: value for k, value in found[role].items() if k != "nested_hashes"}
            for role in ROLES
        ],
        "relationships": {
            "v28_identical_across_three_locations": True,
            "living_circuit_v3_identical_across_two_locations": True,
            "source_authenticity_verified": False,
        },
        "independent_code_execution": False,
        "nested_archives_extracted": False,
        "partner_source_published": False,
        "independent_signature_verification": False,
        "redistribution_approval_verified": False,
        "independent_xi_peer_authenticated": False,
        "real_two_host_crossing_tested": False,
        "r17_external_pilot": "BLOCKED",
        "r18_real_two_host_pilot": "NOT_RUN",
        "live_xi_connected": False,
        "authority": "none",
        "warnings": warnings,
        "qualification": "Local ZIP/CRC/SHA and attached manifest parity only; manifest is not a trusted signature, test receipt, license or partner approval.",
    }
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", action="append", required=True, metavar="ROLE=LOCAL_ZIP",
                        help="repeat exactly four times for v28, fullstack, architecture, kernel")
    parser.add_argument("--out", type=pathlib.Path, help="write redacted local JSON report")
    args = parser.parse_args(argv)
    paths = {}
    for item in args.bundle:
        if "=" not in item:
            parser.error("--bundle must be ROLE=LOCAL_ZIP")
        role, path = item.split("=", 1)
        if role in paths:
            parser.error("duplicate bundle role")
        paths[role] = pathlib.Path(path)
    try:
        result = audit(paths)
    except IntakeRefused:
        # Refusal reason and local path are not emitted by default; safer in CI logs.
        print(json.dumps({"status": "COLD_INTAKE_REFUSED", "authority": "none",
                          "live_xi_connected": False}, sort_keys=True))
        return 2
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(content, encoding="utf-8")
    print(content, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
