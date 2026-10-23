# Xi Vessel Bridge

**Status:** `v0.1.0-dev` protocol seed  
**Purpose:** a neutral interoperability contract for independently governed AI systems.

Xi Vessel Bridge lets two systems discover selected capabilities, exchange provenance-preserving capsules, request explicitly permitted tools, and return verifiable receipts **without either side surrendering authority over its own runtime**.

The first target pairing is **Super Φ.Vessel** and **ForgeCore**, but the protocol is intentionally implementation-neutral.

## Core rule

> **Capability does not equal authority.**

A peer may advertise that a capability exists. That advertisement never grants permission to invoke it. Every remote operation is separately permission-gated by the receiving system.

## v0.1 handshake

The first conformance path is deliberately small:

1. `hello` — establish protocol/session identity.
2. `capabilities` — advertise only explicitly exposable capabilities.
3. `capsule.offer` — offer one provenance-preserving artifact.
4. `tool.request` — request one named **read-only** operation.
5. `tool.result` — return the result plus a receipt bound to the request.

```text
Vessel A                         Vessel B
   |                                |
   |---------- hello -------------->|
   |<------- capabilities ----------|
   |-------- capsule.offer -------->|
   |<--------- accepted ------------|
   |--------- tool.request -------->|
   |<-- tool.result + receipt ------|
   |                                |
```

## Frozen safety invariants for v0.1

- **Deny by default.** Anything not explicitly exposed is unavailable.
- **Capability ≠ authority.** Discovery never grants execution permission.
- **Request IDs are idempotency keys.** A duplicate accepted request ID MUST NOT execute twice.
- **Provenance survives transit.** Author/source/version/hash/intended-use metadata stays attached.
- **No ambient authority.** Bridge connectivity does not imply filesystem, shell, model, repository, network, or tool access.
- **Receiver decides.** The receiving system may return `denied`, `unavailable`, `not_applicable`, or `expired` without workaround attempts.
- **Either architect may pause the bridge.** Disconnection must not damage either peer's local state.
- **Receipts bind results to requests.** Results must identify the request and operation that produced them.

## Repository layout

```text
spec/                 JSON Schemas for the protocol contract
examples/             Canonical v0.1 packet examples
docs/                 Architecture, security, provenance, handshake, conformance
reference/python/      Small executable reference handshake
tests/                 Dependency-free conformance tests
.github/workflows/     CI for the reference/conformance suite
```

## Transport

`xi.exchange.v1` is transport-agnostic. HTTP, WebSocket, local IPC, message queues, or another authenticated channel may carry the packets. Transport security and peer authentication are mandatory for real deployments but are intentionally separated from packet semantics.

## Authentication

The protocol reserves `auth` and `signature` fields, but **v0.1 does not freeze a cryptographic suite yet**. Implementations must not claim cross-peer authentication merely because a packet contains an identity string. The first local/reference handshake may run without network authentication; any real remote bridge must authenticate its peer at the transport and/or message layer before privileged operations are exposed.

## First operation

The canonical read-only test tool is:

```text
artifact.sha256
```

It accepts capsule bytes (or a locally resolved capsule reference) and returns a SHA-256 digest. It is intentionally boring. Boring is excellent when proving that two autonomous systems can cooperate without accidentally acquiring each other's house keys.

## Non-goals for v0.1

- remote shell access
- arbitrary code execution
- unrestricted filesystem access
- automatic repository writes
- autonomous privilege escalation
- shared secrets in packets or examples
- model invocation unless separately and explicitly exposed
- swarm/agent delegation

## Versioning

Protocol identifier: `xi.exchange.v1`

The JSON Schemas in `spec/` are the source of truth for packet shape. Documentation explains intent; it does not override the schemas.


## R1 staging: Phi at the Table

The first Xi Table adapter is now available as a **local mock only**. It authenticates
synthetic mention events with HMAC-SHA256, enforces a strict event allowlist, rejects
changed-message replay, and stores receipts with durable SQLite deduplication.

**R2 operator hardening:** the CLI now rejects non-loopback bind addresses,
requires an explicit staging room, and supports an immediate local pause switch
(`.xi-table-state/PAUSED`). No production integration is claimed.
The [Hunter ↔ Phi handoff](docs/HUNTER_TABLE_HANDOFF.md) lists the real Table
contract and staging permissions needed for a joint end-to-end trial.

It does **not** yet connect to Hunter's live Table or Super Φ.Vessel. The real Xi
event/posting contract and human-approved permissions must be established first.

- [R1 staging contract and local walkthrough](docs/XI_TABLE_R1.md)
- [Local mock receiver](reference/python/xi_table_r1.py)
- [Signed-event simulator](reference/python/send_mock_table_event.py)
- [Staging tests](tests/test_xi_table_r1.py)

Run all protocol and R1 tests with `python -m unittest discover -s tests -v`.


## R3-A: sealed reciprocal peer fixture (NOT live Xi integration)

R3-A adds an offline two-direction encrypted capsule plus signed receipt
experiment. It uses mutually pinned Ed25519 identities, ephemeral X25519,
HKDF, AES-GCM, and SQLite replay refusal. It preserves .xi text, *supplied*
AST JSON, and provenance without claiming Xi-native AST verification.
No Xi endpoint, actual tessera grant, model, or Room history is accessed.

Run locally after installing the separate PyCA cryptography dependency:

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r3.py
    python -m unittest discover -s tests -v

- [R3-A design, boundaries, safety limits, and Hunter live acceptance gates](docs/XI_PEER_R3.md)
- [Synthetic offline reciprocal demonstration](reference/python/demo_peer_r3.py)
- [Negative-control test suite](tests/test_xi_peer_r3.py)

**Status: OFFLINE_RECIPROCAL_FIXTURE_VERIFIED; LIVE_XI_CONNECTED = false.**
The native Xi wire contract, approved staging transport, and real two-runtime
exchange remain to be verified before enabling any production integration.

## R4: two-process loopback transport fixture

A new **OFFLINE-ONLY** integration test now launches Xi and Phi as **separate local OS processes**, each with its own disposable test keys. It sends an encrypted, signed offer to a strictly loopback-only fixture HTTP service and validates a signed encrypted receipt on the return path. Negative controls test unsafe destinations, unauthorized peers, wrong room, tampering, replay, operator pause and private profile permissions.

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r4.py

See [R4 transport fixture and limits](docs/XI_PEER_R4.md). No production Xi endpoint, private credential, Super Phi Vessel model, or Table posting connection is involved. **LIVE_XI_CONNECTED remains false.**

## R5: operator-granted peer admission (offline fixture)

A signed/encrypted capsule is not an authorization. R5 adds an **opt-in** operator-controlled local grant gate to the R4 fixture, restricted to one sender, recipient, stage, operation and short time interval. The gate is checked after authenticity and decryption but before event replay reservation; revocation is reloaded per request without a server restart. All tests use synthetic identities and private local files.

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r5.py

See [R5 proof and limitations](docs/XI_PEER_R5.md). There is no Xi endpoint, live Table seat, real tessera key, or model invocation. **LIVE_XI_CONNECTED remains false.**

## R6: grant pinning and monotonic revocation (local fixture)

R6 adds a durable local SQLite grant ledger: first approved use pins a grant ID and its exact scope/expiry; revocation creates a tombstone that survives server restart and old JSON file restoration. It also adds an operator CLI for explicitly revoking the local synthetic grant. This is a **local filesystem/SQLite protection against accidental rollback, not a production authority or tamperproof record**.

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r6.py

[Read the R6 threat model and reproducible test](docs/XI_PEER_R6.md). The bridge still uses artificial identities only; **LIVE_XI_CONNECTED=false**.

## License

MIT. See `LICENSE`.
