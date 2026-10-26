# R18.10 · Cross-Runtime Ephemeral Ed25519 Receipt Verification

**Status and evidence category:** `SELF_ISSUED_EPHEMERAL_SIGNATURE_MATH_VALID`.

R18.9 established byte-for-byte parity for four frozen **unsigned** synthetic receipts between Python and Node. R18.10 adds a tightly separated cryptographic test: each runtime creates a **fresh, local, random Ed25519 keypair**, signs the same domain-separated R18.9 receipt bytes, and the **other runtime verifies** the signature. The only result this can establish is mathematical self-issued signature correctness. No party authenticates another party's identity, no real Xi partner receives a message and no human authorization is granted.

## Independent implementations

- `reference/python/xi_signed_receipt_r1810.py` uses `cryptography`'s Ed25519 signing and verification and the existing Python R18.9 canonical receipt builder.
- `reference/js/xi_signed_receipt_r1810.cjs` uses Node's built-in `crypto.generateKeyPairSync('ed25519')`, `crypto.sign` and `crypto.verify`, plus the independent Node R18.9 canonical receipt builder.
- No private key is exported, written to disk, logged, committed, included in a fixture, or uploaded as an artifact. Keypairs are **new each emission** and discarded with the process.
- Only the public key (32 raw bytes in lower-case hex), detached signature (64 bytes in lower-case hex), and original public R18.9 receipt bytes (canonical Base64) are exported. A key **inside an untrusted envelope is not a trusted key pin**.
- Each runtime independently regenerates the only permitted R18.9 receipt for one of `digest`, `policy`, `replay`, `revoked`. These are *synthetic case labels*, not observed remote events.

## Cryptographic byte contract

R18.10 signs **exactly** these bytes:

```text
ASCII("PhiXi.R18_10.SelfIssuedSyntheticReceipt.v1") || 0x00 ||
  R18.9_CANONICAL_RECEIPT_BYTES
```

This prefix provides test-domain separation. It is **not a protocol version agreed with Hunter**, a substitute for a real Xi wire contract, or protection against remote replay.

The envelope schema `PhiXi.R18_10_SelfIssuedLocalSignatureFixture.v1` is serialized using R18.9's purposely restricted printable-ASCII, sorted-keys, compact JSON + one final LF. The base64, hex, SHA-256, signature message and case binding are all reverified on import. Size maximum 8,192 bytes. Any changed key, signature, receipt, domain hash, approval flag, schema, unknown field, noncanonical JSON or altered authority marker must fail closed.

The cross-language verification output schema `PhiXi.R18_10_SelfIssuedVerificationReport.v1` includes:

```json
{
  "status": "SELF_ISSUED_EPHEMERAL_SIGNATURE_MATH_VALID",
  "self_issued_signature_verified": true,
  "independent_partner_identity_verified": false,
  "operator_approvals": 0,
  "approved_operations": 0,
  "external_gates_promoted": 0,
  "real_two_host_crossing_tested": false,
  "live_xi_connected": false,
  "authority": "none"
}
```

Other public fields identify the exact scenario and public SHA-256 digests. **No result, even successful, implies Xi has authenticated or consented.**

## CI cross-language gauntlet

```bash
python -m unittest discover -s tests -p 'test_xi_signed_receipt_r1810.py' -v
node --test tests/test_xi_signed_receipt_r1810.cjs

python reference/python/xi_signed_receipt_r1810.py emit --case digest --out python.json
node reference/js/xi_signed_receipt_r1810.cjs verify --file python.json

node reference/js/xi_signed_receipt_r1810.cjs emit --case digest --out node.json
python reference/python/xi_signed_receipt_r1810.py verify --file node.json
```

The existing **Xi Bridge Conformance** workflow performs this roundtrip in both directions for all four R18.9 labels, for a total of **eight independent ephemeral signatures and eight cross-language verifications**. It checks each exported verification report for zero promoted gates, zero approvals, `authority=none`, no Xi connection and no claimed remote testing. The artifact `phi-xi-r18-10-unpinned-ephemeral-signature-cross-verification` contains only public self-issued envelopes and redacted mathematical verification reports, never a private key or source from Hunter's ZIP bundles. Each emission uses random keys, so unlike R18.9 the signed envelopes are **not golden deterministic byte vectors**.

### Adversarial cases covered

- False partner identity, joint consent, approved operations, live status or R17/R18 gate promotion
- Swapped ephemeral public keys, signatures, or signed receipts
- Broken signature, changed domain context/digest or receipt hash
- Extra unknown envelope fields, duplicate JSON keys, invalid Base64 and noncanonical JSON
- Missing terminal LF, whitespace changes, unknown cases, oversized files and `require-live` refusal

## Explicit limitations

This is genuine Ed25519 **signature verification mathematics** but only with **self-issued, unpinned public keys**. Anyone can mint another mathematically valid fixture, so it offers **no trusted sender attribution**. It also does not validate a native Xi recipient, bind a real transport session, establish independent human consent, prove a durable delivery receipt, guarantee replay prevention, or test two physical hosts. No server, API, Cloudflare tunnel, partner source code, private credential, or remote Xi execution is involved.

The next bilateral step is for both operators to independently review public protocol proposals and establish an authenticated, mutually pinned **partner-controlled** identity and consent procedure, with test permissions, revocation and external gates documented beforehand. R18.10 does **not clear any of the 16**.

**LEDGER ABOVE EGO · R17 external pilot BLOCKED · R18 real two-host NOT RUN · LIVE_XI_CONNECTED=false.**
