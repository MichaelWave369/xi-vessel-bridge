#!/usr/bin/env python3
"""R10: read-only intake validator for an UNTRUSTED Xi/Phi staging contract.

This tool does not fetch URLs, call Xi, load tokens or authorize any operation.
A syntactically complete contract is still UNVERIFIED until each operator
checks the independently delivered real Xi documentation and peer identity.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

FORMAT = "xi.phi.partner-intake.candidate.r10"
MAX_BYTES = 32_768
FIELDS = {"format", "classification", "peer", "room", "transport", "authorization",
          "wire", "receipts", "evidence", "limits"}
SHAPES = {
    "peer": {"sender", "recipient"},
    "room": {"room_id", "phi_seat_id", "human_approval_record_sha256"},
    "transport": {"mode", "event_url", "reply_url", "follows_redirects"},
    "authorization": {"mechanism", "scopes", "grant_spec_sha256", "revocation_spec_sha256"},
    "wire": {"capsule_media_type", "native_schema_sha256", "signed_bytes_rule",
             "native_tessera_version"},
    "receipts": {"request_id_field", "receipt_id_field", "idempotency_rule"},
    "evidence": {"official_transport_doc_sha256", "redacted_event_sha256",
                 "redacted_reply_sha256", "out_of_band_peer_signing_key_sha256"},
    "limits": {"max_event_bytes", "timeout_seconds"},
}
READ_SCOPES = {"braid.read", "capsule.read", "local.chat"}
SCOPES = READ_SCOPES | {"table.reply"}
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[a-zA-Z][\w.-]{0,63}\Z")
NON_SECRET_RE = re.compile(r"(?i)(bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]+|sk-[A-Za-z0-9]{8,})")
FORBIDDEN_NAMES = re.compile(r"(?i)(^|_)(password|api_key|private_key|access_token|refresh_token|secret|credential)(_|$)")
UNSAFE_HOST_ENDINGS = (".local", ".localhost", ".internal", ".invalid", ".test", ".example")
PLACEHOLDER = None


class IntakeError(ValueError):
    pass


def _pairs_unique(pairs):
    d = {}
    for name, value in pairs:
        if name in d:
            raise IntakeError("duplicate_json_key")
        d[name] = value
    return d


def strict_load(path: str) -> dict:
    try:
        with open(path, "rb") as file:
            data = file.read(MAX_BYTES + 1)
    except OSError as exc:
        raise IntakeError("input_file_unavailable") from exc
    if not data or len(data) > MAX_BYTES:
        raise IntakeError("input_file_size_invalid")
    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs_unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(IntakeError("invalid_number")))
    except (ValueError, UnicodeError, TypeError) as exc:
        if isinstance(exc, IntakeError):
            raise
        raise IntakeError("invalid_json") from exc
    if not isinstance(parsed, dict):
        raise IntakeError("expected_object")
    return parsed


def candidate_template() -> dict:
    """An UNFILLED review form, not a sample of Hunter's actual contract."""
    return {
        "format": FORMAT, "classification": "staging_candidate",
        "peer": {"sender": "xi", "recipient": "phi"},
        "room": {"room_id": None, "phi_seat_id": None,
                 "human_approval_record_sha256": None},
        "transport": {"mode": "outbound_poll", "event_url": None,
                      "reply_url": None, "follows_redirects": False},
        "authorization": {"mechanism": None, "scopes": ["capsule.read"],
                          "grant_spec_sha256": None, "revocation_spec_sha256": None},
        "wire": {"capsule_media_type": None, "native_schema_sha256": None,
                 "signed_bytes_rule": None, "native_tessera_version": None},
        "receipts": {"request_id_field": None, "receipt_id_field": None,
                     "idempotency_rule": None},
        "evidence": {"official_transport_doc_sha256": None,
                     "redacted_event_sha256": None,
                     "redacted_reply_sha256": None,
                     "out_of_band_peer_signing_key_sha256": None},
        "limits": {"max_event_bytes": None, "timeout_seconds": None},
    }


def synthetic_complete_fixture() -> dict:
    """Reserved .invalid hostname and fake evidence digests: NEVER usable live."""
    result = candidate_template()
    result["classification"] = "synthetic_fixture"
    result["peer"] = {"sender": "xi-fixture", "recipient": "phi-fixture"}
    result["room"].update(room_id="synthetic-fixture-room", phi_seat_id="phi-fixture")
    result["transport"]["event_url"] = "https://xi-fixture.example.invalid/v1/fixture/events"
    result["authorization"]["mechanism"] = "ed25519"
    result["wire"].update(capsule_media_type="application/vnd.xi.fixture+json",
                          signed_bytes_rule="canonical-json",
                          native_tessera_version="test-fixture-not-native-tessera")
    result["receipts"].update(request_id_field="request_id",
                              receipt_id_field="receipt_id",
                              idempotency_rule="one-receipt-per-request-id")
    result["limits"].update(max_event_bytes=8192, timeout_seconds=10)
    for section, keys in [
        ("room", ["human_approval_record_sha256"]),
        ("authorization", ["grant_spec_sha256", "revocation_spec_sha256"]),
        ("wire", ["native_schema_sha256"]),
        ("evidence", list(result["evidence"])),
    ]:
        for key in keys:
            result[section][key] = hashlib.sha256(
                ("synthetic-fixture:" + section + ":" + key).encode()).hexdigest()
    return result


def _scan_secret_like(value, *, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise IntakeError("invalid_field_names")
            if FORBIDDEN_NAMES.search(key):
                raise IntakeError("secret_field_prohibited")
            _scan_secret_like(child, path=path + "." + key)
    elif isinstance(value, list):
        for item in value:
            _scan_secret_like(item, path=path)
    elif isinstance(value, str):
        if NON_SECRET_RE.search(value) or "-----BEGIN" in value or "uploads/mikey-tessera" in value:
            raise IntakeError("secret_like_value_prohibited")
        if len(value) > 2_048:
            raise IntakeError("field_value_too_large")


def _valid_url(value: object, *, synthetic: bool) -> bool:
    if not isinstance(value, str) or len(value) > 512 or any(c.isspace() for c in value):
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or not parsed.path.startswith("/")
                or not parsed.path or parsed.username or parsed.password
                or parsed.fragment or parsed.query or parsed.port == 0):
            return False
        host = host.lower()
        if any(host == "localhost" or host.endswith(s) for s in (".localhost", ".local", ".internal")):
            return False
        if not synthetic and (host in {"example.com", "example.org", "example.net"}
                              or host.endswith(UNSAFE_HOST_ENDINGS)):
            return False
        if not synthetic and not "." in host:
            return False
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host))
        else:
            # Metadata only, but never certify literal internal/public IP host
            # as a partner's *documented, authenticated DNS hostname*.
            return False
    except (ValueError, TypeError):
        return False


def validate(candidate: object) -> dict:
    """Fail hard on unsafe content; return a redacted list of missing proofs.

    A complete contract is only 'reviewable', NEVER 'connected', 'approved'
    or 'trusted'. The validator does not authenticate any supplied digest.
    """
    if not isinstance(candidate, dict) or set(candidate) != FIELDS:
        raise IntakeError("contract_shape_invalid")
    _scan_secret_like(candidate)
    if candidate["format"] != FORMAT:
        raise IntakeError("unknown_contract_version")
    classification = candidate["classification"]
    if classification not in ("synthetic_fixture", "staging_candidate"):
        raise IntakeError("classification_forbidden")
    synthetic = classification == "synthetic_fixture"
    for section, expected in SHAPES.items():
        value = candidate[section]
        if not isinstance(value, dict) or set(value) != expected:
            raise IntakeError("contract_section_invalid_" + section)

    issues = []
    def need(name: str, condition: bool):
        if not condition:
            issues.append("missing_or_unverified:" + name)

    peer = candidate["peer"]
    need("peer_ids", all(isinstance(peer[k], str) and ID_RE.fullmatch(peer[k]) for k in peer))
    if peer["sender"] == peer["recipient"]:
        raise IntakeError("same_peer_denied")

    room = candidate["room"]
    for k in ("room_id", "phi_seat_id"):
        need("room." + k, isinstance(room[k], str) and bool(ID_RE.fullmatch(room[k])))
    transport = candidate["transport"]
    if transport["mode"] != "outbound_poll":
        raise IntakeError("unsolicited_inbound_transport_denied")
    if transport["follows_redirects"] is not False:
        raise IntakeError("redirect_following_denied")
    need("transport.event_url", _valid_url(transport["event_url"], synthetic=synthetic))
    if transport["reply_url"] is not None:
        if not _valid_url(transport["reply_url"], synthetic=synthetic):
            raise IntakeError("unsafe_reply_url")

    auth = candidate["authorization"]
    need("authorization.mechanism", auth["mechanism"] in ("bearer", "ed25519"))
    scopes = auth["scopes"]
    if (not isinstance(scopes, list) or not scopes or
            any(not isinstance(x, str) or x not in SCOPES for x in scopes)
            or len(set(scopes)) != len(scopes)):
        raise IntakeError("unapproved_or_duplicate_scope")
    if "table.reply" in scopes:
        need("table.reply_endpoint", transport["reply_url"] is not None)
        need("table.reply_explicit_human_approval",
             isinstance(room["human_approval_record_sha256"], str)
             and bool(SHA_RE.fullmatch(room["human_approval_record_sha256"]))
             and room["human_approval_record_sha256"] != "0" * 64)
    elif transport["reply_url"] is not None:
        raise IntakeError("reply_url_without_reply_scope")
    for section in ("room", "authorization", "wire", "evidence"):
        part = candidate[section]
        for k, v in part.items():
            if k.endswith("_sha256"):
                need(section + "." + k, isinstance(v, str) and bool(SHA_RE.fullmatch(v))
                     and v != "0" * 64)

    wire = candidate["wire"]
    need("wire.capsule_media_type", isinstance(wire["capsule_media_type"], str)
         and bool(re.fullmatch(r"application/[a-zA-Z0-9.+-]{2,80}", wire["capsule_media_type"])))
    need("wire.signed_bytes_rule", wire["signed_bytes_rule"] in ("canonical-json", "raw-utf8", "exact-bytes"))
    need("wire.native_tessera_version", isinstance(wire["native_tessera_version"], str)
         and len(wire["native_tessera_version"].strip()) > 3
         and wire["native_tessera_version"] != "pending")

    receipts = candidate["receipts"]
    for key in ("request_id_field", "receipt_id_field"):
        need("receipts." + key, isinstance(receipts[key], str) and bool(ID_RE.fullmatch(receipts[key])))
    need("receipts.idempotency_rule", receipts["idempotency_rule"] in (
        "one-receipt-per-request-id", "dedupe-before-post", "reject-duplicate-id"))

    limits = candidate["limits"]
    need("limits.max_event_bytes", type(limits["max_event_bytes"]) is int
         and 1 <= limits["max_event_bytes"] <= 65536)
    need("limits.timeout_seconds", type(limits["timeout_seconds"]) is int
         and 1 <= limits["timeout_seconds"] <= 60)

    # A complete proposal cannot self-authorize: no operational actions are
    # executed here, and partner provenance remains unverified.
    return {
        "status": ("R10_INTAKE_INCOMPLETE" if issues else
                   "R10_SYNTHETIC_SHAPE_VERIFIED" if synthetic else
                   "R10_STAGING_CANDIDATE_REQUIRES_JOINT_REVIEW"),
        "contract_sha256": hashlib.sha256(json.dumps(candidate, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest(),
        "classification": classification,
        "missing_requirements": sorted(set(issues)),
        "supplied_documents_authenticated": False,
        "operator_approval_verified": False,
        "peer_keys_verified": False,
        "transport_invoked": False,
        "live_xi_connected": False,
    }


def write_new(path: str, document: dict) -> None:
    target = Path(path)
    if target.exists() or target.is_symlink():
        raise IntakeError("refuse_overwrite_or_symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False).encode() + b"\n")


def main():
    p = argparse.ArgumentParser(description="R10 NO NETWORK Xi partner contract intake")
    sub = p.add_subparsers(dest="cmd", required=True)
    for cmd in ("template", "synthetic"):
        sub.add_parser(cmd).add_argument("--out", required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--file", required=True)
    inspect.add_argument("--require-complete", action="store_true")
    args = p.parse_args()
    try:
        if args.cmd == "template":
            write_new(args.out, candidate_template())
            report = validate(candidate_template())
        elif args.cmd == "synthetic":
            fixture = synthetic_complete_fixture()
            write_new(args.out, fixture)
            report = validate(fixture)
        else:
            report = validate(strict_load(args.file))
        print(json.dumps(report, indent=2, sort_keys=True))
        if args.cmd == "inspect" and args.require_complete and report["missing_requirements"]:
            return 2
        return 0
    except (IntakeError, ValueError, TypeError, OSError) as exc:
        p.error(str(exc) if isinstance(exc, IntakeError) else "invalid_or_unsafe_contract")


if __name__ == "__main__":
    sys.exit(main())
