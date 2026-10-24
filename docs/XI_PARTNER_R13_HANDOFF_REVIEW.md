# R13: Partner Bundle Intake, Quarantine & Actual Evidence Gate

**Why now:** On October 23, 2026, Plex returned an actual 8,812-byte handoff archive to Mikey after R12. Archive SHA-256: `d20b535ad2ea8ca934b2277c6b948ffa3dddd72f2eb6ae6dfc84587d6c6ceced`. The archive is intentionally **not committed**: it contains third-party Python source and unverifiable partner identity claims. Keep it as user-held evidence, not our executable dependency.

## What independently matches

- The received archive's SHA-256 matches the string shared in the Xi room.
- Its nine pinned inner files all match their published byte lengths and SHA-256 values.
- R12 reports eight self-reported matches: exact bytes, Unicode, provenance, corrupted-digest denial, wrong-room denial, revoked-grant denial, unknown-tool refusal, and duplicate-delivery idempotency.
- R10 structurally complete contract reports `R10_STAGING_CANDIDATE_REQUIRES_JOINT_REVIEW`.
- R11 verification reports two signatures, `R11_DUAL_REVIEW_SIGNATURES_VERIFIED_NOT_AUTHORIZED`.

**None of these observations independently authenticate the uploader, the deployed Xi runtime, the approval record, transport endpoints or an actual room-scoped grant.**

## Confirmed deficits in supplied runner (inspect, do not execute)

1. `XiR12PartnerAdapter` is a newly created `sqlite3.connect(":memory:")` in-memory emulator with hardcoded room/grant/operations. It does **not** connect to `room.xi-field.com` or exercise the published transport.
2. The supposed `evidence.out_of_band_peer_signing_key_sha256` is the SHA-256 of the Xi federation Python *source file*, repeated verbatim from `authorization.revocation_spec_sha256`. This is **not** a public signing key digest.
3. `evidence.official_transport_doc_sha256` hashes **this repository's** `docs/HUNTER_TABLE_HANDOFF.md`, not an independently authenticated Xi operator's documented transport contract.
4. `wire.native_schema_sha256` points to our `spec/xi.exchange.v1.schema.json`, not a independently authenticated Xi-native TESSERA specification.
5. The runner creates **both** Xi and Φ R11 review keys using `Ed25519PrivateKey.generate()`. Role-separated cryptographic keys do not create two independent reviewers. The report explicitly says `keys_independently_authenticated: false`, `grant_issued: false` and `transport_invoked: false`.
6. The R11 request is time-bounded: issued 2026-10-23 17:22:07 Pacific; expired 17:32:07 Pacific the same day. R13 rechecks historic signature validity only, never grants present/future permission.
7. The R10 requested scopes include `table.reply` (a response capability); even a successful read-only acceptance should not silently include reply/post permissions.

These are **correctable partner-intake defects**, not evidence that the Xi team acted dishonestly. The reporter and independent reviewers already acknowledged much of this distinction.

## Offline R13 triage

```sh
python reference/python/xi_partner_r13_intake.py \
  --archive /local/private/path/to/handoff.tar.gz \
  --expected-sha256 d20b535ad2ea8ca934b2277c6b948ffa3dddd72f2eb6ae6dfc84587d6c6ceced
```

R13 reads bounded tar bytes without extraction or running bundled Python. It compares the externally supplied checksum to the archive, checks every nine-item file pin and size, independently re-assesses R12 using **our** R12 engine, revalidates R10 and checks R11 signatures at their historical request time. It identifies the digest mispin and self-issued source patterns where present. No secrets, network calls, partner imports, transport or permission change.

The expected output is always `R13_VERIFIED_BYTES_FIXTURE_ONLY_LIVE_BLOCKED`. `--require-live` **must return nonzero**, even with perfect archive bytes. Checksum alone cannot authenticate the source of a checksum.

The tool's limited allowlist only accepts this R10/R11/R12 handoff shape. Any new handoff format needs separate review. No tar extraction, arbitrary member names, symlinks, unexpected Python files, duplicate keys or extra archive files are accepted.

## Specific next partner acceptance criteria

**Xi side:**
- Provide a real public **Ed25519 signing public key** (never a private key) with its exact byte encoding and a second out-of-band operator-verifiable identity pin; correct the R10 key digest. Document how its Xi identity is established and rotated.
- Supply the authentic transport/openapi or native protocol documentation **as bytes**, together with the correct SHA-256; distinguish the Xi-owned schema from our `xi.exchange.v1` proposal.
- Supply **redacted real request/reply records and deployed endpoint receipts**, not our own example artifacts. A non-secret, revocable scoped staging grant should bind the exact operator seat, room, capability, expiry, and transport. No direct transfer of bearer secrets in chat.
- Sign only the Xi reviewer role after human/operator review, with its independently operator-held key.

**Φ / Mikey side:**
- Independently pin peer identity through an authenticated second channel; independently review the corrected exact R10 contract bytes.
- Generate and keep Φ's own distinct review key private under the Φ operator's control. Sign only the `phi_reviewer` role, following explicit user approval, against a **fresh** R11 request with expiry and revocation.
- Run the initial crossing from Φ's own trusted host, **outbound and read-only**. Do not hand Xi, browser agents or the conversation shell any private key or credential. Never run the supplied third-party Python script as a prerequisite.
- Independently capture authenticated TLS transport request IDs, delivered event/reply payload digests, scope/room checks, replay denial and failure results.

**Acceptance remains blocked** until transport, identity, grants, consent and actual Xi execution evidence are independently verified. A fake fixture, all-green CI suite, or syntactically complete contract cannot substitute.

## Credential warning

The Xi-room statement says a rotated **private ForgeCore key** sits at `/root/.xi/mikey-forgecore.key` and is accessible to several seats. That raises custody questions; an authentication credential stored on a different operator's server is not automatically under Mikey's exclusive control. Verify provenance, storage and access with the human operator, rotate if exposure is possible, and never send that key or bearer token in chat. Our acceptance tools require no such key.

**Ledger above ego. Interop above imitation.**
