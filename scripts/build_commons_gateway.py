#!/usr/bin/env python3
"""Build the R17.3 static public Commons Gateway.

All inputs are versioned PHI-side source fixtures. No Xi calls, credentials,
third-party tar execution, privileged data access or external fetches.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
import xi_capability_r171 as cap
import xi_pilot_r18 as pilot
import xi_shared_roadmap_r17 as roadmap

SOURCE = ROOT / "roadmap"
PACKETS = (
    ("request.json", cap.make_request),
    ("synthetic-fixture.json", lambda _: pilot.fixture()),
    ("pilot-preflight-draft.json", lambda _: pilot.draft()),
    ("transcript-template.json", lambda _: pilot.empty_transcript()),
)
STATIC_FILES = {
    "commons.html": "index.html",
    "commons.css": "commons.css",
    "commons.js": "commons.js",
    "index.html": "roadmap.html",
    "capabilities.html": "capabilities.html",
    "intake.html": "intake.html",
    "intake-core.js": "intake-core.js",
    "intake.js": "intake.js",
    "bridge-roadmap.json": "bridge-roadmap.json",
    "capability-registry.json": "capability-registry.json",
    "manifest.webmanifest": "manifest.webmanifest",
    "lab.html": "lab.html",
    "lab.css": "lab.css",
    "lab.js": "lab.js",
    "lab-core.js": "lab-core.js",
}
SCHEMA = "PhiXi.PublicHandoffManifest.R17_3.v1"


class BuildRefused(ValueError):
    pass


def canonical(doc):
    return json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    if not path.is_file() or path.is_symlink():
        raise BuildRefused("missing or symlinked static source file: " + path.name)
    return path.read_bytes()


def build(destination):
    reg = cap.validate_registry(cap.read_json(SOURCE / "capability-registry.json"))
    plan = roadmap.validate(json.loads(regular(SOURCE / "bridge-roadmap.json")))
    if plan["live_xi_connected"] is not False or plan["authority"] != "none":
        raise BuildRefused("unapproved roadmap authority")
    if reg["public_advertised_count"] != plan["xi_public_preview"]["capabilities_count"]:
        raise BuildRefused("Xi preview count mismatch")
    if destination.is_symlink():
        raise BuildRefused("output path is a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    public_files = {}
    for source, target in STATIC_FILES.items():
        public_files[target] = regular(SOURCE / source)
    if b"__VERSION__" not in regular(SOURCE / "sw.template.js"):
        raise BuildRefused("service worker missing cache version substitution")
    for name, data in public_files.items():
        path = destination / name
        if path.is_symlink():
            raise BuildRefused("refusing to overwrite symlinked output")
        path.write_bytes(data)

    # Public UI preview is generated from the R18.1 fixed *summary contract*,
    # not a fresh execution or a cross-host witness. Never include keys or raw transcripts.
    witness = {
        "status": "R18_1_TWO_HOUSE_LOCAL_SIMULATION_PASS",
        "process_count": 2, "distinct_ephemeral_identity_keys": True,
        "bilateral_r16_handshake": True,
        "signed_xi_exchange_v1_shaped_digest_roundtrip": True,
        "bidirectional_local_digest": True,
        "durable_request_replay_refused_after_restart": True,
        "receiver_pause_refused": True,
        "receiver_revocation_survived_restart": True,
        "source_fixture_sha256": pilot.sha(pilot.PAYLOAD),
        "permitted_operation": "artifact.sha256", "cross_host_network": False,
        "physical_hosts": 1, "real_xi_peer_verified": False,
        "two_physical_hosts_confirmed": False, "live_xi_connected": False,
        "r17_external_pilot": "BLOCKED", "r18_real_two_host_pilot": "NOT_RUN",
        "authority": "none",
        "qualification": "Two local synthetic processes, fixture-only cryptography and permissions."
    }
    preview = {
        "schema": "PhiXi.R18_2_LocalLabPreview.v1",
        "preview_only": True, "classification": "illustrative_fixture_not_fresh_run",
        "witness": witness
    }
    preview_bytes = canonical(preview)
    (destination / "lab-preview.json").write_bytes(preview_bytes)
    public_files["lab-preview.json"] = preview_bytes

    packet_dir = destination / "handoff"
    if packet_dir.is_symlink():
        raise BuildRefused("handoff target cannot be a symlink")
    packet_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for name, maker in PACKETS:
        doc = maker(reg)
        if name == "synthetic-fixture.json":
            pilot.verify_fixture(doc)
        elif name == "pilot-preflight-draft.json":
            if pilot.inspect_preflight(doc)["pilot_status"] != "BLOCKED_PENDING_INDEPENDENT_PROOF":
                raise BuildRefused("pilot preflight unexpectedly promoted")
        elif name == "transcript-template.json":
            if pilot.inspect_transcript(doc)["status"] != "NOT_RUN":
                raise BuildRefused("pilot transcript unexpectedly promoted")
        if isinstance(doc, dict) and (doc.get("live_xi_connected") is True or
                                     doc.get("authority", "none") != "none"):
            raise BuildRefused("public packet contains an unapproved live claim")
        data = canonical(doc)
        if len(data) > 32768:
            raise BuildRefused("unexpected public handoff byte size")
        (packet_dir / name).write_bytes(data)
        entries.append({
            "name": name, "size_bytes": len(data), "sha256": digest(data),
            "classification": "synthetic_public"
        })
        public_files["handoff/" + name] = data

    man = {
        "schema": SCHEMA, "snapshot_date": reg["snapshot_date"],
        "source_registry_sha256": cap.document_hash(reg),
        "files": entries,
        "live_xi_connected": False, "authority": "none",
        "disclosure": "Locally generated synthetic handoff; not a live Xi signature, grant or authorized receipt."
    }
    manifest_bytes = canonical(man)
    (packet_dir / "manifest.json").write_bytes(manifest_bytes)
    public_files["handoff/manifest.json"] = manifest_bytes

    version_input = b"".join(name.encode("utf-8") + b"\0" + digest(data).encode("ascii") + b"\n"
                             for name, data in sorted(public_files.items()))
    cache_version = digest(version_input)[:16]
    worker = regular(SOURCE / "sw.template.js")
    worker = worker.replace(b"__VERSION__", cache_version.encode("ascii"))
    (destination / "sw.js").write_bytes(worker)
    report = {
        "status": "PUBLIC_STATIC_GATEWAY_BUILT",
        "schema": SCHEMA, "static_assets": len(public_files) + 1,
        "public_packet_files": len(PACKETS), "cache_version": cache_version,
        "r17_external_status": "BLOCKED",
        "r18_two_host_status": "NOT_RUN",
        "live_xi_connected": False, "authority": "none"
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    args = parser.parse_args(argv)
    try:
        result = build(args.out.resolve())
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (BuildRefused, cap.Refused, roadmap.RoadmapRefused, pilot.Refused,
            OSError, ValueError, UnicodeError) as exc:
        print(json.dumps({"status": "REFUSED", "reason": type(exc).__name__,
                          "live_xi_connected": False, "authority": "none"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
