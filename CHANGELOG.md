# Changelog

## v0.1.0-dev — 2026-09-13

Initial interoperability seed.

- Defined the `xi.exchange.v1` envelope.
- Defined capability, capsule, tool-request, tool-result, and receipt schemas.
- Froze deny-by-default and capability-not-authority invariants.
- Added canonical `artifact.sha256` read-only handshake fixtures.
- Added provenance requirements and request-ID idempotency semantics.
- Added dependency-free Python reference implementation and conformance tests.
- Added CI workflow for the reference suite.

### ForgeCore interoperability review hardening

- Replaced the reference receipt placeholder with an RFC 3339 / JSON-Schema-compatible UTC date-time.
- Bound request replay fingerprints to sender/session context, the complete request payload, and exact capsule bytes.
- Added conformance tests proving changed input and changed capsule bytes cannot reuse an accepted request ID.
- Documented the first-crossing strategy for the older ForgeCore/Vessel `xi.exchange.v1` envelope.
- Specified base64 carriage of exact legacy UTF-8 packet bytes to prevent accidental changes from JSON parse/reserialization.
- Recorded ForgeCore's native read-only verification and grammar routes as candidate interoperability targets without falsely claiming that bridge aliases, cross-peer credentials, signatures, or durable idempotency already exist.

This is a development contract, not a production security profile.
