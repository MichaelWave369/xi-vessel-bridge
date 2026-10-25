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


def verify_site(url=BASE, fetcher=fetch_public, *, expected_manifest=None):
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
    insist(b"Shared Bridge Roadmap" in page and b'id="milestones"' in page and\n           b"./bridge-roadmap.json" in page,
           "Published roadmap page is missing")
    workbench = fetcher(url + "intake.html")
    insist(b"Partner Intake Workbench" in workbench and b"Local inspection only" in workbench,
           "Published partner intake UI missing or unexpected")
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
        "checked_public_resources": 6 + len(PACKETS),
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
    p.add_argument("--attempts", type=int, default=1)
    p.add_argument("--delay", type=float, default=0)
    args = p.parse_args(argv)
    if not 1 <= args.attempts <= 15 or not 0 <= args.delay <= 30:
        print(json.dumps({"status": "REFUSED", "reason": "invalid probe bounds"}))
        return 2
    for attempt in range(args.attempts):
        try:
            report = verify_site(args.url, expected_manifest=args.expected_manifest)
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
