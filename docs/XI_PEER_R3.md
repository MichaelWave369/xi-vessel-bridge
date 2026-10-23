# R3-A: Reciprocal sealed capsule fixture

**Status: OFFLINE_RECIPROCAL_FIXTURE_VERIFIED (local developer tests). LIVE_XI_CONNECTED = false.**

R3-A is a deliberately independent **test-only peer envelope**. It does not implement Hunter's native .xi AST grammar, TESSERA v4 codec, Xi Table event/reply API, or ForgeCore's official transport format. The label **xi.phi.peer.fixture.r3** belongs only to this repository until both teams approve an actual contract.

## What R3-A demonstrates

1. A signed and AES-GCM-encrypted message carries exact .xi text, supplied AST JSON, and explicit author/source/version/intended-use provenance, with SHA-256 of the text bytes. **This does not prove the AST is a correct semantic parse of the .xi text.**
2. Public identity keys are pinned out of band. Incoming packets do not get to supply new trusted identities. An Ed25519 signature covers the canonical envelope; the receiver verifies the trusted signer before decrypting.
3. A fresh ephemeral X25519 sender key, HKDF-SHA256 and AES-256-GCM bind message confidentiality and integrity to the sender/recipient/stage/request/time/nonce context.
4. Allowed packet types are only **capsule.offer** and **capsule.receipt**. Unexpected tool commands, room history, shell instructions, credentials, attachments and extra fields are refused by the fixture's payload validator.
5. A durable SQLite replay store atomically rejects a previously used sender/request UUID, including after restart. A pause file stops even repeated packets.
6. The second peer returns a separately signed, encrypted fixture receipt binding the original request ID and full offer-payload SHA-256. Its decision is **fixture_verified**, not evidence of a posted Xi message or authorized agent execution.

**Security limits:** There is no transport server in R3-A. The recipient's X25519 key is static, so past recorded messages are not forward-secret against later compromise of that key. No enrollment, key rotation, HSM, denial-of-service controls, remote peer access, live credential loading, ratcheting, identity attestation, AST validation or independent security audit is provided.

## Run the harmless fixture

Requires Python 3.12+ and the declared PyCA cryptography dependency:

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r3.py
    python -m unittest discover -s tests -v

The demo uses two **disposable, memory-only identities**, named phi-fixture and xi-fixture; no key material is written to disk. The example does not contact Xi, Super Phi Vessel, localhost HTTP, Ollama, GitHub, or any other service. The sanitized result explicitly reports **real_xi_connected: false**.

## Hunter's reported work versus independently verified work

Hunter's Oct 23 Room transcript reports a revocable, no-admin peer grant, local .xi/AST/provenance testing, mock capsule compatibility, and a lossless four-name TESSERA v4 test. We have **not independently reproduced the private Xi receipts**, verified its actual staging API contract, or completed a live reciprocal crossing. An HTTP 422 reported after a valid-key request with no prompt is insufficient to establish the complete inference contract, and an inference grant does not establish Table posting permission.

**R3-A never reads the private Room credential** reportedly stored at uploads/mikey-tessera-25661.key, or the welcome package at uploads/mikey-welcome-25673/. Keep the real grant out of GitHub, CI, chats, screenshots and logs. Store it locally, restrict its download access, and rotate if it has been exposed.

## Joint R3-B acceptance gates (not yet satisfied)

- [ ] Hunter and Mikey agree on official Xi wire/schema/AST/TESSERA parsing rules, signed-byte canonicalization, peer identity pinning and key rotation. Preserve native Xi data as opaque bytes until mapping is verified.
- [ ] Confirm the real grant scopes, actual documented endpoints, redacted request/response examples, rate limits, and precise 401/403/422 meanings; never invent these from an error message.
- [ ] Approve a separate staging room, exact seat identity, peer enrollment and a private credential handoff. Prefer authenticated outbound HTTPS and avoid an exposed local webhook.
- [ ] Exchange one benign capsule in **both directions** between separately operated Xi and Phi runtimes; obtain independently recorded runtime receipts.
- [ ] Verify exact .xi source bytes, AST interpretation against Xi's parser, provenance, both party signatures and confidentiality controls.
- [ ] Verify tamper, wrong-room, unknown-peer, expired-grant, revocation, pause and replay negative controls. Confirm no default private-room-history transfer and no implied tool execution.
- [ ] Both human operators review redacted evidence; mark only the specific tested capability LIVE_XI_CONNECTED, not the entire Xi Table.

**Capability does not equal authority. Ledger above ego. Fixture pass does not equal live integration.**
