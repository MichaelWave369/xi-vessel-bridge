# R18.9 · Independently reproducible public receipt bytes (Python ⇄ Node)

**Classification:** `UNAUTHENTICATED_PUBLIC_SYNTHETIC_BYTE_PARITY`.

R18.8 proved self-consistency of the four supplied Xi/QuantumCompute archives without running or republishing them. R18.9 is deliberately narrower and more testable: implement a **Φ-authored candidate receipt byte profile in two independent languages**. They must produce exactly the same canonical byte strings, each verify the other's output, and compare to immutable public SHA-256 golden hashes.

This is a first interoperability exercise for our *own* candidate format. It is **not** Hunter's confirmed Xi-native protocol, a signed TESSERA packet, partner endorsement, a live machine exchange, a receipt actually produced by Xi, or bilateral cryptographic identity proof.

## Frozen input and exactly four case labels

The input is the 88-byte `PhiXi.R18SyntheticFixture.v1` already defined by `reference/python/xi_pilot_r18.py`:

```text
PHI-XI R18 SYNTHETIC DIGEST FIXTURE v1
NO PRIVATE DATA; NO AUTHORITY; NO REMOTE RIGHTS.
```

Its byte SHA-256 is `8370bdb1f706a2168accc1c225a37c98ec907cd3e954b67c1cdcc9d8ddd8feb5`.

The four permitted candidate labels are `digest`, `policy`, `replay` and `revoked`. They are **illustrative labels**, not claims that an operation, remote policy decision, replay or revocation happened. Every receipt states `example_only=true`, `observed_exchange=false`, `independent_signatures_verified=0`, `operator_approvals=0`, `approved_operations=0`, `live_xi_connected=false`, `authority=none`, R17 `BLOCKED` and real R18 two-host `NOT_RUN`.

The receipt schema is `PhiXi.R18_9_PublicIllustrativeReceipt.v1` and byte profile `PhiXi.R18_9.ASCII_SORTED_JSON.v1`.

## Canonicalization contract (NOT RFC 8785 / JCS)

This is a deliberately restricted, **ASCII-only JSON** profile rather than a claim to implement all of the IETF JSON Canonicalization Scheme.

1. Root is an object of exact preapproved fields and values; unknown/extra fields are refused.
2. Object keys are lexicographically sorted, recursively; arrays preserve declared order.
3. Use compact JSON with `,` and `:` separators and no extra whitespace.
4. Only printable ASCII keys/strings, nonnegative safe integers, and booleans are accepted. No floats, negative numbers, null, Unicode, control characters, dynamic timestamps, operator-supplied text, keys, endpoints, or signatures.
5. Encode as ASCII/UTF-8 and end with **exactly one LF byte**. Limit the complete receipt to 4 KiB.
6. The verifier independently regenerates the *only allowed* byte string for the case label, then compares **every original byte**, not just a computed digest.
7. Duplicate JSON keys are rejected in Python during parsing. Node accepts no non-identical raw representation, so duplicate-key input fails its mandatory byte comparison even if `JSON.parse` would otherwise accept it.

This minimal profile is intentionally easy to audit and implement across languages. Other Unicode or numeric payloads require a **new, independently reviewed versioned profile**.

## Published golden digests

These values were calculated independently from the frozen Python JSON construction and pinned in `fixtures/r189-golden-digests.json`. Both implementations verify the published byte counts and hashes.

| Case | Canonical receipt bytes | SHA-256 |
|---|---:|---|
| `digest` | 653 | `83c985315e442ff41bd6d3fe15ff4d894a94cccfb0dcf8140dd333643728645c` |
| `policy` | 660 | `016d5783e1417fd9fcab70c2283a2e3fd3e8b834ab76e5f61edfd9e3caaafa34` |
| `replay` | 660 | `f58db92c866ee61e4be24edff79c960b9daf4b0372a35383997bf1cbb56f17ff` |
| `revoked` | 658 | `69c9019a24a76ddb6bf5c5b7e1092694de8fe4e29d37a49a0c04769dd0f80fd4` |

These are **integrity fingerprints of our publicly constructed example bytes**, not authentication of a partner or guarantee of authenticity. An adversary can compute the same hash.

## Reproduction (no partner ZIPs required)

Requires only Python 3.12+, Node 20+; the Python tool imports the existing standard-library `xi_pilot_r18.py` source.

```bash
python reference/python/xi_receipt_r189.py emit --case digest --out python-digest.json
node reference/js/xi_receipt_r189.cjs emit --case digest --out node-digest.json
cmp python-digest.json node-digest.json

python reference/python/xi_receipt_r189.py verify --file node-digest.json
node reference/js/xi_receipt_r189.cjs verify --file python-digest.json

python -m unittest discover -s tests -p 'test_xi_receipt_r189.py' -v
node --test tests/test_xi_receipt_r189.cjs
```

The conformance workflow performs all steps for **all four cases** and uploads the unsigned, nonsecret canonical byte examples plus `public-receipt-bytes.sha256` in GitHub Actions artifact `phi-xi-r18-9-unsigned-public-canonical-receipt-parity`. No Xi private source, keys or endpoint is added to this repository.

### Negative controls

Both implementations refuse unknown cases, altered digests/bytes, different object key ordering, different whitespace, missing LF, duplicate fields, extra object fields, false signer claims, claimed operator approvals, privileged operations, live Xi claims, scope expansion, and malformed or unsupported JSON values. The `require-live` command deliberately exits with status 2 in both languages.

## Next human-governed interoperability step

Hunter's side can independently review this *public proposal*, then suggest whether any part maps to their actual native receipt contract. The two houses must separately agree on **protocol version, exact byte encoding, key binding, algorithm suite, replay model, sender identity validation, operator consent and independent revocation**. Only then could a future signed external witness be attempted.

**Do not feed these unsigned illustrative receipts into authorization decisions or count this test as clearing any of the 16 bilateral readiness gates.**

**R17 external pilot BLOCKED · R18 real two-host crossing NOT RUN · Xi peer unauthenticated · authority=none.**

LEDGER ABOVE EGO · Source bytes before trust.
