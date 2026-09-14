# ForgeCore Compatibility — First Crossing

**Status:** handoff-alignment note for `xi.exchange.v1` v0.1 development.  
**Scope:** preserve an existing, older ForgeCore/Vessel packet format while testing the new neutral bridge envelope.

## Discovery

ForgeCore already has a Vessel helper that identifies its packets as `xi.exchange.v1`, but that existing envelope predates this repository and is structurally different from the bridge contract defined here.

The first crossing MUST NOT silently reinterpret the legacy packet as though it already conformed to the new envelope.

## Preservation strategy

For the first interoperability crossing:

1. The **outer packet** uses the new Xi Vessel Bridge envelope.
2. The **inner legacy packet** is carried as capsule content.
3. The legacy packet's exact source bytes are hashed before transit.
4. The receiver verifies those exact bytes after decoding.
5. No field translation is treated as authoritative until a separate mapping specification and fixtures exist.

This gives us a bridge around the legacy packet rather than pretending the two packet grammars are already the same.

## Exact-byte carriage

For a JSON legacy packet whose original bytes are known to be UTF-8, the preferred v0.1 carriage is:

- capsule `format`: an implementation-specific legacy-format label;
- content `media_type`: `application/json`;
- content `encoding`: `base64`;
- content `data`: base64 of the **exact original UTF-8 bytes**;
- content `sha256`: SHA-256 of those same original bytes;
- content `size_bytes`: original byte length.

Base64 is preferred for the compatibility fixture because parsing and reserializing JSON can change whitespace, escaping, key order, or line endings even when the parsed object is semantically equivalent. The first crossing is testing preservation, so byte identity matters.

The outer bridge capsule provenance describes who packaged the preserved artifact and why. It MUST NOT overwrite the provenance contained inside the legacy packet.

## Candidate native read-only ForgeCore routes

The ForgeCore handoff identifies these existing native routes as useful read-only candidates:

### Capsule verification

```text
POST /api/xi/v1/fabric/verify
```

- accepts an inline `XiFabric.v1` capsule;
- verifies without storing;
- is a strong first native interoperability target after the shared `artifact.sha256` baseline.

### Tessera grammar discovery

```text
GET /api/xi/v1/tessera/grammar
```

- returns grammar information;
- is suitable for later capability/discovery work.

Bridge-level aliases for these native routes are **not frozen in this document**. They should be adopted from the ForgeCore handoff package or mutually agreed fixtures rather than invented independently here.

## Transport and authentication reality

ForgeCore currently uses HTTP JSON and bearer authentication on protected native routes.

That is useful existing infrastructure, but it MUST NOT be represented as if the cross-peer bridge requirements are already complete. In particular, bridge work still needs explicit decisions for:

- peer credential provisioning;
- credential rotation/revocation;
- optional message signatures;
- durable request-ID/idempotency storage;
- reconnect/retry behavior;
- bridge-specific authorization policy.

No credential, token, key, or private endpoint belongs in this repository or its fixtures.

## Receipt truthfulness

A fixture receipt is an expected test vector, not evidence that a remote bridge executed. Documentation and examples MUST distinguish:

- **fixture/expected receipt** — what a conforming implementation should return; from
- **runtime receipt** — what an actual receiver reports after an operation.

Runtime receipts must satisfy `spec/receipt.schema.json`, including a valid date-time.

## Replay binding

A request ID is safe as an idempotency key only when its cached fingerprint binds the operation to the security-relevant request semantics and exact artifact input.

The reference implementation therefore binds replay fingerprints to:

- sender identity when present;
- session ID when present;
- the full request payload, including its complete `input` object;
- the exact capsule bytes.

A matching request ID with different bound content is rejected as `request_id_conflict` and MUST NOT execute.

## First joint milestone

The first honest cross-system milestone remains intentionally narrow:

```text
preserve one packet
    -> expose/discover one agreed read-only capability
    -> submit one request
    -> execute exactly once
    -> return one result + runtime receipt
    -> verify artifact/result identity on both sides
```

Neither ForgeCore nor Super Phi Vessel becomes a dependency, authority source, or privileged runtime of the other merely because this crossing succeeds.
