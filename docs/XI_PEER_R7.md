# R7: Public witness kit for Hunter and Xi

**OFFLINE, SYNTHETIC AND SELF-SIGNED. No live Xi/ForgeCore/Table connection is claimed.**

R3 proved local sealed frames, R4 proved a two-process loopback transport, and R5/R6 added operator-granted revocation. R7 makes those **test-frame claims portable and inspectable by a third party** without sharing or embedding private keys.

## Share this with Hunter

After R7 CI passes, GitHub Actions will attach a public-only artifact named **xi-r7-public-witness** to the Xi Bridge Conformance workflow run on PRs and branch pushes. It contains **one JSON file**, not a private grant, database, or user conversation.

The source is also reproducible in a fresh Python 3.12 environment:

    python -m pip install -r requirements-r3.txt
    python reference/python/xi_peer_r7_handoff.py export --out r7-public-handoff.json
    python reference/python/xi_peer_r7_handoff.py verify --file r7-public-handoff.json

You can use a file downloaded from Actions as the argument to verify. No network access is needed during verification.

### What is actually inside

- Two newly generated **disposable** fixture identities, phi-fixture and xi-fixture, represented only by Ed25519 and X25519 **public** keys. Signing/encryption private keys are held in RAM during export only and are never serialized.
- An innocuous synthetic .xi string and accompanying synthetic AST-like JSON, explicitly **NOT** output from Xi's native .xi compiler.
- One encrypted, signed offer frame and a separately signed, encrypted receipt frame. The generator privately checks a full Phi → Xi → Phi round trip before exporting.
- SHA-256 of the disclosed synthetic offer and receipt payloads, an explicit receipt link to the original request ID, and three negative-control tampered frames.
- A verifier that independently checks the public Ed25519 signatures, exact canonical JSON-byte binding, payload hashes, route/stage declarations, receipt-to-offer association, and rejection of all three tampered vectors.

The verifier does **not** decrypt the ciphertext; its output explicitly says decryption_checked_by_public_verifier:false. A fresh export produces different random keys, request IDs, ciphertext and signatures. This is an independently runnable demonstration, **not a fixed golden test vector or identity proof**.

## Interpretation of a PASS

The outcome R7_PUBLIC_WITNESS_VERIFIED means: under the particular **self-asserted public keys included in this test file**, the two frames have valid signatures, the synthetic public payloads have consistent digests and receipt links, and known test modifications fail signature validation.

It does NOT prove either named participant is the real Xi or Super Phi Vessel runtime, that the packet was delivered between two physical machines, that Xi's native AST conforms to the synthetic JSON, that TESSERA v4 decrypts it, or that any Room message was actually posted. A malicious person could manufacture a different internally consistent self-signed fixture. Trust requires **independently pinned operational keys and independently observed endpoint receipts**.

## What we need from Hunter for the first real crossing

See also [machine-readable staging contract questions](XI_R7_CONTRACT_REQUEST.json) and [Hunter Table handoff](HUNTER_TABLE_HANDOFF.md).

- Redacted native event/response examples, official request schema and actual allowed endpoints for ONE approved staging operation. Do not infer a posting URL from the inference endpoint.
- Signed-byte or canonicalization rules and the genuine .xi/TESSERA AST mapping. A sealed synthetic JSON frame must not silently be called a native Xi tessera.
- Human-approved test room/seat, **specific** per-operation grant scope, sender enrollment/public-key pinning and expiration/revocation rules. No private token in an issue, repository or chat transcript.
- How and where each peer can independently record the same test transaction ID, original payload digest and returned receipt.
- Expected negative-control outcomes for wrong peer, wrong scope, tampered bytes, replay, revoked key and operator pause.
- Decide whether Xi pushes a staging event or the Phi peer polls an authenticated Xi queue. Prefer no unsolicited public listener on a private workstation.

Once that contract and credentials are arranged privately, a separate live integration branch can map documented Xi semantics and capture independently verified, redacted results. Until then this remains **LOCAL_ONLY**.

**Capability does not equal authority. Ledger above ego.**
