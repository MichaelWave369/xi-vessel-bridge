# R8: Public plaintext-to-ciphertext witness (synthetic disclosure)

**OFFLINE / SELF-SIGNED TEST DATA ONLY. LIVE_XI_CONNECTED=false.**

R7 proved its publicly supplied Ed25519 signatures were valid and that the
*separately disclosed* synthetic payload/receipt digests were internally
consistent. However, without the recipient's decryption key, a public
verifier could not establish that the *signed ciphertext* actually encrypted
the **same disclosed payload bytes**. A malicious author could replace the
public offer/AST and recompute those detached hashes while preserving the
original ciphertext and valid signatures.

R8 closes this **public fixture evidence gap** without exporting identity
private keys.

## What is disclosed, exactly?

The generator uses two brand-new, disposable fixture identities and
discloses **only the 32-byte symmetric AES-GCM content key for each of its two
synthetic test frames**. It derives each key from the already generated
fixture's X25519 secret exchange and signed frame header (HKDF-SHA256).
No long-lived Ed25519 signing private key or X25519 identity private key is
exported. No live Xi tessera, model token or Room data is imported.

**These two public test-frame ciphertexts are deliberately NOT
confidential.** Anyone can decrypt their synthetic messages. This is
acceptable only because the plaintext is innocuous and already public.
**Never publish content keys from a real bridge session or any frame
containing private information.** R8's exporter hard-codes its synthetic
test content; it is not a general decryption/export command.

## Reproduce independently

Use Python 3.12+:

    python -m pip install -r requirements-r3.txt
    python reference/python/xi_peer_r8_disclosed.py export --out r8-witness.json
    python reference/python/xi_peer_r8_disclosed.py verify --file r8-witness.json
    python -m unittest discover -s tests -v

The verifier:

1. Performs the entire **R7 public signature and detached receipt verification**.
2. Uses only the **two disclosed one-message AES-256-GCM keys** to decrypt
   the signed offer and receipt frames.
3. Checks their authenticated additional data (the complete canonical signed
   header) and the built-in AEAD tags.
4. Asserts the exact decrypted UTF-8 bytes equal canonical UTF-8 bytes of the
   separately disclosed offer and receipt, not merely their claimed digests.
5. Refuses mismatches, wrong content keys, altered signatures, tampered frame
   headers, invalid scopes and unknown bundle fields.

A successful result is
**R8_PUBLIC_PLAINTEXT_BINDING_VERIFIED**, reporting two decrypted/comparable
frames and three rejected test mutations. The old R7 report remains accurate
but narrower: **R7 cannot independently check ciphertext plaintext**, while
R8 can for these intentionally disclosed test vectors.

The GitHub Actions conformance workflow uploads the public synthetic JSON as
the short-lived artifact **xi-r8-public-disclosed-witness**. It contains test
content keys, so its file name and provenance explicitly advertise the
confidentiality loss. Download only from a trusted repository run; validate
the script and expected status yourself.

## What this STILL does not prove

- **No native Xi/TESSERA v4 parser or true .xi semantic AST validation.**
- **No live Xi/Φ peer authentication or independently pinned runtime keys.**
  All signatures validate against test keys supplied inside the packet.
- **No real cross-machine or Xi Table message exchange.** The generated
  data comes from a self-contained local fixture, not Hunter's runtime.
- **No remote permission verification, distributed authorization, secure
  hardware, external trust anchor or confidential evidence transport.**
- **No real user data** and no private grant material. The publicly disclosed
  two message keys are deliberately unsuitable for real traffic.

For live integration, use the separate human-approved staging plan in
[Hunter's Table handoff](HUNTER_TABLE_HANDOFF.md) and
[the R7 contract request](XI_R7_CONTRACT_REQUEST.json).
The final Xi wire contract is still an open dependency.

**Capability does not equal authority. Ledger above ego.**
