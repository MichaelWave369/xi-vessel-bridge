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

## License

MIT. See `LICENSE`.
