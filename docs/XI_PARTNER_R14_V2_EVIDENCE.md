# R14: Independently supplied public evidence is required

## Why R14 exists

The actual October 23, 2026 Xi/Plex **v2** handoff archive is 8,653 bytes:
`eb2ae139413ba1db5cef828d5b5100e9242f9f71cadda320f172379ee1bddea2`.
All nine pinned inner files and the R13 structural checks may pass while crucial
**evidence is absent**. A clean set of heuristic source checks means only that
a short list of patterns was not found. It must never be called authentication.

R14 is an additive, offline companion to R13. It does **not** modify R3-R12,
read credentials, load external runtimes, initiate remote requests or claim
to authenticate identities. The partner's Python is never executed, imported
or extracted to disk. It reuses R13's strict bounded archive gate before
reading a tiny allowlisted subset as data.

## Actual v2 observations

- The v2 contract properly reduces scopes to `braid.read`, `capsule.read`,
  `local.chat` and nulls its `reply_url`. Scope selection is a declaration,
  **not an observed grant or proof of read-only runtime behavior**.
- Its R11 document still has a **partner-provided phi_reviewer signature** and
  pin origin `synthetic_self_issued`; its own report says both reviewer
  identities are unauthenticated.
- The runner source's `derive_role_signer(domain_tag)` derives signing
  private keys from `sha256(domain_tag)`. It signs both reviewer roles
  (including `phi.fixture.placeholder...`). This is an explicitly reproducible
  simulation, not an independent Φ review.
- The runner switches from `sqlite3.connect(":memory:")` to `sqlite3.connect(db_path)`,
  but allocates that file inside `tempfile.TemporaryDirectory()`. The
  fixture does not demonstrate recovery after stopping and starting the
  deployed process with the same on-disk state, nor durable cross-restart
  replay protection.
- The **actual** v2 candidate records
  `official_transport_doc_sha256` as
  `b78ba74e9b646f93d8c3b93b507665d7edce0d88356e90ef840aae85949df1bb`
  and `wire.native_schema_sha256` as
  `9c1f33240605ae32004496f0e535d478a3e42bc9ce223e1ff8d47510467c3a32`.
  The shorter/different values in the Xi-room message are **not** these
  candidate values. Neither referenced Xi-owned source document's bytes
  are included in the archive.
- The candidate's raw public signing-key pin is
  `faefc83d7756724aadc078fe122e5d98d230bebf3ad77e576f9918da67fc31dc`.
  Yet SHA-256 of the 32 raw bytes decoded from Plex's advertised public
  base64 string `eibfeafwQ0b2R62pV88k31D0hWbaN5VdeD7naxdBjn4=`
  is **`9ff709023bafa53666a5e6ed85d770eeaf2371a71187749f6d831ea147b13d2d`**.
  These are *different*. Clarify exactly which public key and encoding is
  authoritative. **Neither value is an authenticated out-of-band identity.**
- The R12 assessment remains `R12_SELF_REPORTED_MATCHES_NOT_AUTHENTICATED`
  with eight self-reported matches. `live_xi_connected` remains false.
- R11's v2 request timestamp is 2026-10-23 18:21:43 PDT and its expiry was
  18:31:43 PDT. It is a historical fixture, **not a current authorization**.

## How to run our next independent inspection

For an archive held on your own host:

```bash
python reference/python/xi_partner_r14_evidence.py \
  --archive /path/to/xi_mikey_r10_r11_r12_partner_conformance_v2.tar.gz \
  --expected-sha256 eb2ae139413ba1db5cef828d5b5100e9242f9f71cadda320f172379ee1bddea2 \
  --peer-public-key-base64 'eibfeafwQ0b2R62pV88k31D0hWbaN5VdeD7naxdBjn4='
```

R14 reports `HASH_MISMATCH` for that advertised key, and `MISSING_BYTES`
for each still-absent Xi transport and native-schema document. It reports
all unresolved peer identity, independent Φ review, restart, scoped-grant,
revocation and real transport receipt requirements in `blocking_findings`.

To review new **public** Xi-supplied artifacts, add:

```bash
  --transport-spec /path/to/XI_NATIVE_STAGING_TRANSPORT_SPEC.md \
  --native-schema /path/to/xi.tessera.staging.v2.schema.json
```

These must be authentic original bytes, not invented placeholders. A digest
match reports **`HASH_MATCH_UNAUTHENTICATED`** until the source and operator
identity are proven through a second trusted channel. R14 can also accept
`--peer-public-key-raw-file` (exactly 32 Ed25519 public bytes); it never
accepts or needs a private signing key.

`--require-live` always exits nonzero: offline pinned files are **not** a
live transport witness.

## What we need from Xi next (public/sanitized artifacts only)

1. Corrected public-key bytes and digest with verified Xi operator custody
   and a second independent identity channel. No private keys.
2. Actual Xi-authored versioned transport spec and Xi-native schema file,
   both pinned to the same bytes referenced by R10.
3. **Xi-only** R11 request plus Xi's own independently controlled reviewer
   attestation and public verification key. Leave `phi_reviewer` completely
   empty for Mikey to review and countersign using his own operator-held key
   against a **new, current** request. Do not pre-fill that slot, even as a
   convenience fixture in a purported production review.
4. A repeatable restart/replay receipt from the deployed staging adapter
   with a persistent data directory and distinct process lifetimes. Show
   duplicate request denial and old grant revocation after restart.
5. A proposed **explicit human-approved, minimally scoped read-only**
   acceptance plan from our own host, with independent connection receipts,
   room/scope checks and fully redacted message bodies.

These do not require importing their runner or giving third-party agents a
private ForgeCore token. The independent verifier may be rerun as the public
evidence arrives. A complete public bundle is **necessary**, not sufficient,
for authorizing any live operation.

**LEDGER ABOVE EGO. INTEGRITY IS NOT IDENTITY.**
