# R12: Portable Xi↔Φ partner conformance exercise kit

**Status: OFFLINE SYNTHETIC EXERCISES. NOT Xi-native, not an API contract, not authenticated runtime evidence, and not permission to connect or post.**

Hunter's actual Xi interface has not yet been independently documented for this bridge. R3–R11 established local cryptography, limited grants, witnesses and candidate-review procedures, but **none of those fixtures alone prove a live Xi↔Phi crossing**.

R12 gives both teams a small, readable, executable-by-their-own-choice conformance *questionnaire*, with deliberately non-executable inputs, exact-byte expectations and safe negative controls. It runs entirely offline. It neither knows nor invents a Xi endpoint, and it doesn't execute partner-provided code.

## Generate the public handoff

With Python 3.12+ (R12 itself uses only the standard library):

    python reference/python/xi_partner_r12.py generate --dir r12-output/interop

This creates three JSON files:

- **suite.json**: immutable, deterministic synthetic scenarios with bounded UTF-8/base64 payloads, exact expected SHA-256 digests and distinct request IDs
- **response-template.json**: all eight test observations marked **not_run** with null claims. This is what a partner can copy, fill and return
- **synthetic-example-response.json**: fully filled **fabricated positive-control** response demonstrating the expected shape, **not a genuine Xi test report**

The response file must never contain API keys, bearer tokens, private messages or executable code. It has no open-ended notes field. The only optional peer label is a constrained non-sensitive identifier.

## The eight exercises

| Scenario | Partner's requested observation |
|---|---|
| four_name_opaque_bytes | Keep the **exact UTF-8 bytes** of xi-vessel-bridge, Commonline, FieldAccord, think-tank, in that order |
| unicode_exact_bytes | Preserve multibyte symbols and line breaks byte-for-byte |
| provenance_preserved | Return the supplied opaque payload's SHA-256 and its separately declared synthetic provenance digest |
| declared_digest_tampered | Refuse intentionally incorrect declared payload hash; zero operations |
| wrong_room_denied | Refuse delivery to an unapproved room; zero operations |
| revoked_grant_denied | Refuse a revoked scope; zero operations |
| unknown_tool_never_executed | Refuse an unknown operation; **never** execute a tool |
| duplicate_delivery_idempotent | Duplicated request ID must result in at most one accepted operation; return the original data digest |

**These cases describe desired behavior, not Xi-native packet structures.** The Xi team maps each exercise to its actual API/codec and records only synthetic input/output evidence. Unsupported or not-run cases remain unverified rather than being silently passed. A future native Xi parser must separately verify TESSERA/.xi semantic correctness.

The synthetic fixtures contain NO shell commands, URL calls, executable code, local network listeners, private grant files, actual Table messages or real runtime identities.

## Independently assess a submitted response

    python reference/python/xi_partner_r12.py assess --suite r12-output/interop/suite.json --response r12-output/interop/response-template.json

The default template returns **R12_PARTNER_EVIDENCE_PENDING** and reports 8 unresolved cases.

To check the fabricated positive control:

    python reference/python/xi_partner_r12.py assess --suite r12-output/interop/suite.json --response r12-output/interop/synthetic-example-response.json --require-all-matches

The example returns **R12_SELF_REPORTED_MATCHES_NOT_AUTHENTICATED**. This does **not** establish that an Xi agent ran anything. Anyone can fill a response form; the assessor checks shape, digest equality, count values and exact outcome consistency, **not the truth of the claim**.

`--require-all-matches` exits status 2 for any unresolved or mismatched observations. It does **not** authorize a live peer connection when all observations match.

## What the assessor refuses

- Changed or weakened test corpus: the suite must equal the built-in immutable deterministic fixture
- Incorrect suite hash, changed bytes, missing provenance digest and duplicated or unknown test IDs
- Wrong negative-control denial reasons, claimed processing during denied operations, and duplicate-operation counts above one
- Unknown claims of real Xi identity, new fields containing credentials, unexpected response origin values, or malformed input
- Unmeasured/unsupported entries claiming success or other measurements
- Oversized and duplicate-key JSON files, accidental overwrites of existing output files

Reports are redacted, listing only case IDs, outcome codes, counts and hashes. All reports explicitly state:

    "partner_identity_authenticated": false,
    "actual_xi_runtime_observed": false,
    "native_xi_tessera_verified": false,
    "grant_or_permission_verified": false,
    "tool_or_model_executed": false,
    "live_xi_connected": false

The GitHub Actions workflow runs both the **incomplete partner response** and a **fully synthetic positive-control** against the same immutable suite, as well as the full R3–R11 conformance suite. Its downloadable artifact contains exactly the three harmless fixture files.

## What to hand Hunter

Share this document, the downloadable R12 CI artifact, and [the still-unanswered R10 partner contract questionnaire](XI_PARTNER_R10.md). The Xi team can use the suite as a checklist while implementing its own native, **separately governed** tests. Their response need only contain results and synthetic hashes, never live credentials or a private Room history.

For a truly witnessed reciprocal integration, the teams still must jointly resolve the authoritative Xi staging wire schema, transport, per-seat grants, independently authenticated signing keys, native TESSERA parser expectations and dual-sided receipts. That is a **separate milestone**, not something a self-reported JSON file can prove.

**Ledger above ego. Capability does not equal authority.**
