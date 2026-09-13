# v0.1 Handshake

## Goal

Prove that two independently governed systems can perform one selected read-only operation while preserving provenance and local authority.

## Canonical sequence

### 1. HELLO
Peer A proposes `xi.exchange.v1` and a session identifier.

### 2. CAPABILITIES
Peer B advertises selected capabilities. The canonical fixture exposes `artifact.sha256` as `read_only`.

### 3. CAPSULE OFFER
Peer A offers `xi-demo-capsule-001` with bytes, SHA-256, and provenance.

### 4. CAPSULE RESPONSE
Peer B accepts the capsule for the test. `authority_granted` remains false. Accepting bytes is not equivalent to trusting instructions inside them.

### 5. TOOL REQUEST
Peer A requests `artifact.sha256` under `read_only` permission with a unique `request_id`.

### 6. TOOL RESULT
Peer B hashes the accepted capsule bytes and returns the digest plus a receipt bound to the original request ID.

## Success conditions

A conforming v0.1 reference run demonstrates all of the following:

- both peers use the same session ID;
- the capsule bytes match the declared digest;
- the requested operation was advertised;
- the permission requested is read-only;
- the result digest matches the capsule digest;
- the receipt request ID matches the request;
- replaying the exact request ID does not increment execution count;
- an unadvertised operation is denied.

## Explicitly not proven

This handshake does not prove production authentication, secure key management, arbitrary tool interoperability, model federation, distributed consensus, or autonomous trust.
