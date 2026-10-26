# R18.11 · Simulated Local Public-Key Pin, Rotation and Revocation

**Scope:** `LOCAL_SIMULATED_PIN_MATCH_AND_SIGNATURE_VALID_ONLY`. R18.11 builds on R18.10's genuine Python ↔ Node Ed25519 signature mathematics by testing an independent **local expected-key input**. A signature from an unrecognized key is refused even when its Ed25519 mathematics is valid.

**This is not authenticated Xi identity.** The policies are explicitly labeled `LOCAL_TEST_KEY_COPY_NOT_INDEPENDENTLY_AUTHENTICATED`; the demonstration policy generator **copies a self-issued public key out of the signed fixture**. This is *deliberately NOT an out-of-band identity verification ceremony*. It must never be described as verifying Hunter or Xi or as granting any actual operation.

## Separate inputs and strict profile

- `reference/python/xi_pin_policy_r1811.py` verifies the exact R18.10 signed public synthetic receipt with the **existing** Python signer/verifier and then verifies the signer public key matches a separately read, canonical test-policy file.
- `reference/js/xi_pin_policy_r1811.cjs` does the same independently using Node's crypto stack and the existing Node R18.10 verifier.
- Both require an exact-schema `PhiXi.R18_11_SimulatedLocalPinPolicy.v1` profile: exactly **one active 32-byte raw Ed25519 public key**, optionally up to eight distinct sorted revoked test public keys, integer policy epoch 1–65535, a fixed read-only synthetic scope and flags stating identity not verified and zero authority.
- Unexpected fields, malformed keys, noncanonical ASCII JSON, changed approvals/identity flags, active+revoked overlaps, duplicate revocation records, oversized files and symlinked inputs all fail closed.
- Both return `PhiXi.R18_11_LocalPinVerificationReport.v1` with a SHA-256 fingerprint of the matched **public** test key, not the key itself, and `out_of_band_key_authentication_verified=false`.
- No private key is published, written to the repo or included in CI artifact output.

The policy is a distinct *file and function argument*, not an automatically trusted key read from the signed document. This makes the risk of **a mathematically valid signature from the wrong key** explicit and testable. But it does **not** guarantee whoever populated the local file selected the correct real-world peer: the source of the key still requires independent human/cryptographic verification in a future approved pilot.

## Reproducible cross-runtime test

The helper `scripts/xi_r1811_make_self_derived_test_pin.py` exists **only** to manufacture deliberately unauthenticated local policy fixtures for CI, by copying the public key from a mathematically valid self-issued envelope:

```bash
python reference/python/xi_signed_receipt_r1810.py emit --case digest --out python.json
node reference/js/xi_signed_receipt_r1810.cjs emit --case digest --out node.json

python scripts/xi_r1811_make_self_derived_test_pin.py --from-signed python.json --out test-python-policy.json
python scripts/xi_r1811_make_self_derived_test_pin.py --from-signed node.json --out test-node-policy.json

node reference/js/xi_pin_policy_r1811.cjs verify --file python.json --policy test-python-policy.json
python reference/python/xi_pin_policy_r1811.py verify --file node.json --policy test-node-policy.json
```

The CI workflow runs this for four cases in both directions, *then deliberately swaps the pin policy between two different valid signers*. Both runtimes must refuse. Next, a simulated operator test policy rotates from the earlier Python-generated public key to the Node-generated one, explicitly puts the old public key on the revocation roster, and proves the new signer accepts while the retired signer is refused.

Those are **local process / local file** tests. No Xi Room, network, remote party, actual key confirmation, transport, server, or cross-physical-host communication.

## What R18.11 does not prove

- **No authentic peer identification.** The supplied expected key is explicitly unauthenticated. A different self-signed envelope can be accepted if the local user provides a different expected key; this is normal for a test, not trust establishment.
- **No durable anti-rollback or anti-replay.** Policy epoch numbers can be typed or rolled back by the local user. The test does not have an independent, tamper-resistant high-water mark, trusted registry, or retained revocation store. Do not call this production revocation.
- **No bilateral consent or authorization.** A matching public test key does not grant executable tools, network transport, repository writes, data access or custody of secrets. Even a valid match reports zero approved operations, zero external gates promoted, R17 `BLOCKED`, R18 physical crossing `NOT_RUN`, and `authority=none`.
- **No native Xi protocol sign-off.** This tests PHI-authored R18.9 canonical receipt bytes with R18.10 locally issued test signatures, not Hunter's independently confirmed Xi-native format.
- **No partner source redistribution.** The source ZIP files sent by Hunter's team remain private and are not executed or committed.

## Safety tests

```bash
python -m unittest discover -s tests -p 'test_xi_pin_r1811.py' -v
node --test tests/test_xi_pin_r1811.cjs
```

Negative cases include two **independently generated valid signatures** with the same synthetic operation but different public keys, swapped policy files, revoked old keys, changed epochs, invalid roster, self-reported approval, false trust-origin claims, tampered signature, duplicate JSON fields and explicit `require-live` denial.

GitHub Actions uploads redacted/public test-generated signed envelopes, self-derived *untrusted* policy files and cross-runtime test reports in `phi-xi-r18-11-untrusted-test-pin-rotation-and-refusal`. Do not copy those test pins to a real trust registry.

**Next real-world prerequisite:** both operators separately establish **identity and public-key provenance** by a jointly agreed, secure out-of-band process, agree a versioned native protocol, consent to the narrow scope, specify independent revocation and anti-rollback, and only then consider any separately authorized real two-host test. None of those sixteen external evidence gates is cleared here.

**LEDGER ABOVE EGO · Valid mathematical signature ≠ verified identity ≠ permission.**
