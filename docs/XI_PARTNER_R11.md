# R11: Dual-review signature receipts for a partner staging contract

**OFFLINE REVIEW ONLY. No live Xi connection, no verified human identity, no credentials, no grant, no remote execution.**

R10 checks whether a proposed staging contract has all required metadata, but a complete document could change after an operator reviews it. R11 ties a **single R10 contract SHA-256** to a fresh request and two Ed25519 signatures, one from each separately configured reviewer role.

This is **not a permissions broker**. The recorded decision is literally:

    reviewed_candidate_not_execution_permission

A positive R11 check means two independently expected public keys signed that exact candidate review request. It **does not prove the named humans actually inspected the contract**, the pinned keys were properly enrolled, document hashes refer to genuine Xi sources, or live Xi authorization exists. Both owners must verify those separately, outside GitHub.

## Safe synthetic demonstration

Python 3.12+ and the existing cryptography dependency:

    python -m pip install -r requirements-r3.txt
    python reference/python/xi_partner_r11.py fixture --dir r11-output/demo
    python reference/python/xi_partner_r11.py verify --contract r11-output/demo/contract.json --request r11-output/demo/request.json --xi-attestation r11-output/demo/xi-attestation.json --phi-attestation r11-output/demo/phi-attestation.json --pins r11-output/demo/self-issued-demo-pins.json --ledger .xi-peer-state/r11-verified.sqlite3

The fixture generates random disposable signing keys **in RAM** and saves only a synthetic R10 contract, request, two signatures, and a **self-issued** public-key pin file. It never exports signing private keys, a real room ID, real source data, or private credentials. Repeating the same verification using the ledger must fail with `review_replayed`.

## Review of a real, still-untrusted R10 candidate

After Hunter shares a redacted candidate document through an approved channel, first run R10 validation and **manually verify its referenced authoritative documents and partner public-key fingerprints**. R11 will not do that research or authentication for you.

A bounded review-only request is generated with:

    python reference/python/xi_partner_r11.py issue --contract staging-candidate.json --out review-request.json

Each person can *optionally* use their own independently provisioned local **raw 32-byte Ed25519 signing seed** and the following command on their own secure machine:

    python reference/python/xi_partner_r11.py sign --contract staging-candidate.json --request review-request.json --role xi_reviewer --private-key PRIVATE_OPERATOR_KEY_PATH --out xi-attestation.json

The Phi reviewer instead uses role `phi_reviewer` and their own separately controlled key and output file. Signing only attests that the key holder signed a **review-only statement**, not that they approved access. Keys must be provisioned independently, protected by OS file permissions and never transferred into this repo, CI, a public issue or the conversation. This demo expects an owner-only, non-symlink 32-byte key file on POSIX; it is NOT a production HSM or password vault, and equivalent Windows ACL safety is not established.

To verify, obtain the expected **public** signing keys independently and place them in a local, separately maintained pin file matching the fixture's exact pin schema. The pinned keys must be authenticated to the actual operators out of band, not accepted from the candidate or response package.

    python reference/python/xi_partner_r11.py verify --contract staging-candidate.json --request review-request.json --xi-attestation xi-attestation.json --phi-attestation phi-attestation.json --pins reviewer-pins.json --ledger .xi-peer-state/r11-real-review-ledger.sqlite3

The `origin` claim in the pin document is **not independently verified**. A complete result only reports:

    R11_DUAL_REVIEW_SIGNATURES_VERIFIED_NOT_AUTHORIZED

Explicit result flags `keys_independently_authenticated`, `human_approval_verified`, `grant_issued`, `transport_invoked`, and `live_xi_connected` remain **false**, by design.

## Boundaries and tests

- Contract SHA-256, room ID, scope set, classification, request UUID and expiry are bound to the review request. Changing any of them fails verification.
- Exactly **two distinct pinned signing keys** are required for `xi_reviewer` and `phi_reviewer`. Missing, substituted, forged or role-swapped signatures fail.
- The signed decision cannot be escalated from *reviewed* to *authorized* by editing fields.
- An unfinished R10 candidate cannot issue a review request.
- The request expires after 10 minutes, and the verifying CLI reserves accepted request IDs in a local durable SQLite ledger to refuse repeated evidence.
- The ledger prevents repeat use on the same local machine, not distributed replay on another machine. Anyone with full control of pin files, signing keys, validator code, and local SQLite state can defeat this test-layer control.
- Signature verification proves possession of a private key, not real-world identity or an operator's consent. Production requires independently verified credentials, human procedure, source provenance, revocation and secure key custody.
- No network call, Xi/TESSERA parser, actual staging seat or capability is enabled here. R11 does not authorize posting or models.

For the remaining Xi-specific requirements see [R10 staging contract intake](XI_PARTNER_R10.md), [Hunter handoff](HUNTER_TABLE_HANDOFF.md) and [R7 native contract questions](XI_R7_CONTRACT_REQUEST.json).

**Capability does not equal authority. Ledger above ego.**
