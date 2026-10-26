#!/usr/bin/env python3
"""R17.5: independently probe the public GitHub Pages gateway.

Proves only that the static public site, exact published packet bytes, and
source-bound zero-authority claims are reachable via the expected HTTPS origin.
This is NOT proof of a live Xi peer, consent, identity or protocol crossing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))
import xi_capability_r171 as registry_tools

HOST = "michaelwave369.github.io"
BASE = "https://michaelwave369.github.io/xi-vessel-bridge/"
MANIFEST_SCHEMA = "PhiXi.PublicHandoffManifest.R17_3.v1"
PACKETS = (
    "request.json", "synthetic-fixture.json",
    "pilot-preflight-draft.json", "transcript-template.json"
)
MAX_BYTES = 128 * 1024


class NotVerified(ValueError):
    pass


def insist(test, why):
    if not test:
        raise NotVerified(why)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def validate_base(url):
    insist(url == BASE, "Only the fixed canonical GitHub Pages URL can be certified")
    parsed = urlparse(url)
    insist(parsed.scheme == "https" and parsed.hostname == HOST and
           parsed.path == "/xi-vessel-bridge/" and not parsed.query and not parsed.fragment and
           parsed.username is None and parsed.password is None,
           "Unexpected site origin or base path")
    return url


def fetch_public(url):
    parsed = urlparse(url)
    insist(parsed.scheme == "https" and parsed.hostname == HOST and
           parsed.path.startswith("/xi-vessel-bridge/"),
           "Refusing unreviewed external request")
    req = Request(url, headers={"User-Agent": "PhiXi-PublicGateway-Verification-R17.5",
                                 "Accept": "text/html,application/json,*/*"})
    with urlopen(req, timeout=12) as response:
        resolved = urlparse(response.geturl())
        insist(resolved.scheme == "https" and resolved.hostname == HOST and
               resolved.path.startswith("/xi-vessel-bridge/"),
               "External redirect left the approved public origin")
        insist(response.status == 200, "Public Pages responded with non-200")
        raw = response.read(MAX_BYTES + 1)
        insist(len(raw) <= MAX_BYTES, "Public resource is unexpectedly large")
        return raw


def parse_json(raw, name):
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise NotVerified("Invalid JSON: " + name) from exc
    insist(isinstance(obj, dict), "Unexpected document body: " + name)
    return obj


def verify_site(url=BASE, fetcher=fetch_public, *, expected_manifest=None, expected_lab_preview=None):
    validate_base(url)
    home = fetcher(url)
    insist(b"Two houses." in home and b"NOT ESTABLISHED" in home and
           b"./handoff/manifest.json" in home and b"./roadmap.html" in home,
           "Gateway landing page has not reached the public origin")
    manifest_raw = fetcher(url + "handoff/manifest.json")
    manifest = parse_json(manifest_raw, "manifest")
    insist(manifest.get("schema") == MANIFEST_SCHEMA and
           manifest.get("live_xi_connected") is False and
           manifest.get("authority") == "none" and
           isinstance(manifest.get("files"), list) and
           len(manifest["files"]) == len(PACKETS),
           "Manifest is missing or claims unauthorized runtime")
    manifest_hash = sha256(manifest_raw)
    if expected_manifest is not None:
        insist(expected_manifest == manifest_hash,
               "Deployed manifest differs from tested build")
    registry_raw = fetcher(url + "capability-registry.json")
    reg = parse_json(registry_raw, "registry")
    try:
        registry_tools.validate_registry(reg)
    except registry_tools.Refused as exc:
        raise NotVerified("Deployed registry failed non-authorizing contract") from exc
    insist(manifest.get("source_registry_sha256") == registry_tools.document_hash(reg),
           "Published handoff is bound to a different registry")
    page = fetcher(url + "roadmap.html")
    insist(b"Shared Bridge Roadmap" in page and b'id="milestones"' in page and
           b"./bridge-roadmap.json" in page,
           "Published roadmap page is missing")
    workbench = fetcher(url + "intake.html")
    insist(b"Partner Intake Workbench" in workbench and b"Local inspection only" in workbench,
           "Published partner intake UI missing or unexpected")
    lab_html = fetcher(url + "lab.html")
    insist(b"Two-House Operator Console" in lab_html and b"LIVE XI CONNECTION: NOT ESTABLISHED" in lab_html and
           b"./lab-core.js" in lab_html and b"./lab.js" in lab_html,
           "Published R18.2 local-only operator console is missing")
    preview_raw = fetcher(url + "lab-preview.json")
    lab_preview = parse_json(preview_raw, "lab-preview")
    witness = lab_preview.get("witness")
    insist(lab_preview.get("schema") == "PhiXi.R18_2_LocalLabPreview.v1" and
           lab_preview.get("preview_only") is True and
           lab_preview.get("classification") == "illustrative_fixture_not_fresh_run" and
           isinstance(witness, dict) and
           witness.get("status") == "R18_1_TWO_HOUSE_LOCAL_SIMULATION_PASS" and
           witness.get("physical_hosts") == 1 and witness.get("process_count") == 2 and
           witness.get("live_xi_connected") is False and
           witness.get("authority") == "none" and
           witness.get("real_xi_peer_verified") is False and
           witness.get("r18_real_two_host_pilot") == "NOT_RUN",
           "Published lab preview asserts unexpected external evidence")
    preview_hash = sha256(preview_raw)
    if expected_lab_preview is not None:
        insist(expected_lab_preview == preview_hash,
               "Deployed lab preview differs from tested build")
    lab_core = fetcher(url + "lab-core.js")
    lab_script = fetcher(url + "lab.js")
    insist(b"R18_1_WITNESS_SHAPE_VALID_ONLY" in lab_core and
           b"redactedReview" in lab_core and b"IMPORTED_UNTRUSTED_WITNESS" in lab_script and
           b"file.arrayBuffer()" in lab_script,
           "Published lab core/viewer missing or unexpected")
    fault_page = fetcher(url + "fault.html")
    insist(b"Failure-Injection Sandbox" in fault_page and
           b"connect-src 'none'" in fault_page and
           b"./fault-core.js" in fault_page and b"./fault.js" in fault_page and
           b'id="r184-file"' in fault_page,
           "Published R18.3 browser-only sandbox absent or unsafe")
    fault_core = fetcher(url + "fault-core.js")
    fault_ui = fetcher(url + "fault.js")
    fault_css = fetcher(url + "fault.css")
    insist(b"PhiXi.R18_3_LocalFaultScenario.v1" in fault_core and
           b"ILLUSTRATIVE_DETERMINISTIC_BROWSER_SIMULATION" in fault_core and
           b"runAll()" in fault_ui and b"validateWorkerReport" in fault_core and
           b"file.arrayBuffer()" in fault_ui and len(fault_css) > 100,
           "Published R18.3 browser-only simulator assets are missing")
    room_page = fetcher(url + "room.html")
    room_css = fetcher(url + "room.css")
    room_js = fetcher(url + "room.js")
    insist(b"Xi Room Re-entry Briefing" in room_page and
           b"EXTERNAL PILOT BLOCKED" in room_page and
           b"REAL TWO-HOST TEST NOT RUN" in room_page and
           b"connect-src 'none'" in room_page and
           b'./room.js' in room_page and
           b'40254943486' in room_page and
           len(room_css) > 400 and b"navigator.clipboard.writeText" in room_js and
           b"field.select()" in room_js,
           "Public R18.5 nonsecret room briefing not deployed or unsafe")
    gate_page = fetcher(url + "gates.html")
    gate_core = fetcher(url + "gates-core.js")
    gate_ui = fetcher(url + "gates.js")
    gate_css = fetcher(url + "gates.css")
    insist(b"Bilateral Pilot Gate Board" in gate_page and
           b"16 / 16 EXTERNAL GATES OUTSTANDING" in gate_page and
           b"connect-src 'self'" in gate_page and
           b"./gates-core.js" in gate_page and
           b"./gates.js" in gate_page and
           b"PUBLIC_UNAPPROVED_DISCUSSION_AGENDA" in gate_core and
           b"OUTSTANDING_SOURCE_GATE" in gate_core and
           b'fetch("./bridge-roadmap.json"' in gate_ui and
           len(gate_css) > 500,
           "Published R18.6 discussion-only gate board absent or unsafe")
    charter_page = fetcher(url + "charter.html")
    charter_css = fetcher(url + "charter.css")
    charter_core = fetcher(url + "charter-core.js")
    charter_script = fetcher(url + "charter.js")
    insist(b"Synthetic Pilot Charter Studio" in charter_page and
           b"connect-src 'self'" in charter_page and
           b"Human approval from either house" in charter_page and
           b"./charter-core.js" in charter_page and b"./charter.js" in charter_page and
           b"PhiXi.R18_7_ProposedSyntheticPilotCharter.v1" in charter_core and
           b"UNAPPROVED_PUBLIC_PROPOSAL" in charter_core and
           b"approved_operations:0" in charter_core and
           b'checkedJson("./handoff/pilot-preflight-draft.json")' in charter_script and
           len(charter_css) > 500,
           "Published R18.7 non-authorizing charter is missing or unreviewed")
    worker = fetcher(url + "sw.js")
    insist(b"phi-xi-commons-public-" in worker and b"__VERSION__" not in worker,
           "Generated offline worker is absent or unversioned")
    verified = []
    for index, name in enumerate(PACKETS):
        entry = manifest["files"][index]
        insist(isinstance(entry, dict) and entry.get("name") == name and
               entry.get("classification") == "synthetic_public" and
               type(entry.get("size_bytes")) is int and 0 < entry["size_bytes"] <= 32768 and
               isinstance(entry.get("sha256"), str) and len(entry["sha256"]) == 64,
               "Unexpected synthetic packet manifest entry")
        raw = fetcher(url + "handoff/" + name)
        insist(len(raw) == entry["size_bytes"] and sha256(raw) == entry["sha256"],
               "Published synthetic packet does not match manifest: " + name)
        verified.append(name)
    return {
        "verification": "PUBLIC_STATIC_GATEWAY_VERIFIED",
        "schema": "PhiXi.GatewayAvailabilityEvidence.R17_5.v1",
        "public_url": url,
        "manifest_sha256": manifest_hash,
        "registry_sha256": registry_tools.document_hash(reg),
        "checked_public_resources": 25 + len(PACKETS),
        "r18_7_scope": "UNAPPROVED_SYNTHETIC_PUBLIC_CHARTER_NO_REMOTE_AUTHORITY",
        "r18_6_scope": "SIXTEEN_OUTSTANDING_DISCUSSION_ONLY_NO_AUTHORITY",
        "r18_5_scope": "PUBLIC_NONSECRET_ROOM_BRIEFING_NO_EXTERNAL_AUTHORITY",
        "r18_3_scope": "BROWSER_ONLY_DETERMINISTIC_NO_CRYPTO",
        "lab_preview_sha256": preview_hash, "lab_scope": "ILLUSTRATIVE_AND_UNTRUSTED_IMPORTS_ONLY",
        "verified_synthetic_packets": verified,
        "live_xi_connected": False,
        "r17_external_pilot": "BLOCKED",
        "r18_real_two_host_pilot": "NOT_RUN",
        "authority": "none",
        "qualification": "Public HTTPS static files verified; no authentication of Xi operators or evidence of runtime crossing."
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", default=BASE)
    p.add_argument("--expected-manifest", help="SHA-256 of tested local dist/handoff/manifest.json")
    p.add_argument("--expected-lab-preview", help="SHA-256 of tested local dist/lab-preview.json")
    p.add_argument("--attempts", type=int, default=1)
    p.add_argument("--delay", type=float, default=0)
    args = p.parse_args(argv)
    if not 1 <= args.attempts <= 15 or not 0 <= args.delay <= 30:
        print(json.dumps({"status": "REFUSED", "reason": "invalid probe bounds"}))
        return 2
    for attempt in range(args.attempts):
        try:
            report = verify_site(args.url, expected_manifest=args.expected_manifest,
                                 expected_lab_preview=args.expected_lab_preview)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        except (NotVerified, OSError, TimeoutError, ValueError) as exc:
            if attempt == args.attempts - 1:
                print(json.dumps({"status": "PUBLIC_SITE_NOT_VERIFIED",
                                  "reason": type(exc).__name__,
                                  "live_xi_connected": False, "authority": "none"}))
                return 1
            time.sleep(args.delay)
    return 1


if __name__ == "__main__":
    sys.exit(main())
