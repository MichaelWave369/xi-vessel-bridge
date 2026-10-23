# R9: External pins + fresh challenge (synthetic-only)

**Status: OFFLINE FIXTURE ONLY. No genuine Xi identity, native TESSERA verification, remote peer exchange, or Room posting. LIVE_XI_CONNECTED=false.**

R8 independently decrypts two synthetic test frames, but the test packet includes its own signing keys. A verified signature against a key supplied by the same packet is **not** evidence that the signer is the real Xi or Phi peer. R9 demonstrates the missing trust boundary: a verifier must supply a fresh challenge **and independently pinned expected public keys**, outside the response file.

## How to run the three-party handoff

Install Python 3.12+ and the declared PyCA cryptography library:

    python -m pip install -r requirements-r3.txt
    python reference/python/xi_peer_r9_challenge.py challenge --out r9-challenge.json
    python reference/python/xi_peer_r9_challenge.py respond --challenge r9-challenge.json --out r9-response.json --pins-out r9-demo-pins.json
    python reference/python/xi_peer_r9_challenge.py verify --challenge r9-challenge.json --response r9-response.json --pins r9-demo-pins.json --ledger .xi-peer-state/r9-verified.sqlite3

R9's **fixture** responder creates two fresh disposable Ed25519/X25519 identities, as in R3–R8, and writes the keys' PUBLIC signing keys to a **separate demo pin file**. That file is not authentic simply because it is separate! In a real crossing the verifier must independently receive and approve the actual Xi and Phi peer public-key fingerprints (for example, via a separately authenticated direct human-to-human channel). **Never trust a pin file returned by an untrusted responder.**

The challenge issuer independently generates a random 32-byte nonce, a UUID, an explicit fixture audience and an expiry (180 seconds). It does **not** read an external service or secret.

The responder returns:

- An R8 self-signed witness containing synthetic, intentionally disclosed plaintext-test message keys.
- The same two fixture **frame signing identities** also sign the SHA-256 hash of the separate verifier challenge and the complete R7 witness hash.
- The response never contains the verifier's pin file, a signing private key, an actual Xi tessera grant, or private Room content.

The verifier must separately receive all of the following: the challenge it issued, the response, **and the expected pinned public keys**. It checks the live challenge lifetime, full R8 AEAD/plaintext/frame-verification path, exact public-key matches, BOTH attestation signatures and exact challenge/witness digests.

A durable SQLite challenge ledger is required by the CLI to prevent any challenge UUID from being accepted twice. Attempting to reverify the same response returns challenge_replayed; a different response against that UUID returns challenge_conflict. This is **local demo anti-replay state**, not a distributed trust or consensus service.

Expected first successful result:

    {
      "status": "R9_EXTERNAL_PIN_CHALLENGE_VERIFIED",
      "signers_against_external_pins": 2,
      "challenge_bound_signatures": 2,
      "disclosed_fixture_frames_decrypted": 2,
      "synthetic_keys_self_issued": true,
      "live_xi_connected": false,
      "native_xi_verified": false
    }

## What CI proves

- No verification succeeds without a separately passed pin file and challenge.
- A second self-signed fixture cannot impersonate the original identity merely by bringing its own valid signing keys.
- Replaying a receipt with another verifier nonce or changing attested witness bytes fails.
- A signature from the wrong pinned key is rejected; an expired/future challenge is refused.
- Challenge replay is denied across process restart; permissions do not silently expand.
- R3–R8 security/compatibility suites continue running unmodified.

A CI artifact named xi-r9-self-issued-challenge-fixture contains **three public, synthetic files** (challenge, response and the explicitly self-issued demo pin file). It is useful as a reproducible *protocol exercise*, not as a real trust anchor. The R8 content keys are included deliberately so the test plaintext is disclosed. Do not apply R8/R9 disclosure mode to any non-synthetic data.

## Before authenticating Hunter's real Xi

The **outstanding dependency** is an authenticated human-to-human exchange of the REAL Xi/Φ peer signing identities, a mutually approved staging contract, compatible native Xi .xi/TESSERA grammar, and an actually executed reciprocal operation.

Those identities must be enrolled/pinned outside untrusted packets, with rotation and revocation. Do not infer access from an HTTP 422, a signed fixture with self-issued keys, or an uploaded key filename. **Do not put the private tessera grant, model credentials or transcripts into GitHub, this test kit, or chat.** See [Hunter handoff](HUNTER_TABLE_HANDOFF.md) and [Xi staging contract questions](XI_R7_CONTRACT_REQUEST.json).

**Capability does not equal authority. Ledger above ego.**
