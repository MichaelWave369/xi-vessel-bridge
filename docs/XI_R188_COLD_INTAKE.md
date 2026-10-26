# Xi → Φ R18.8 · Cold Intake and Compatibility Boundary

## What this milestone does

Hunter's team supplied four ZIP files to the Φ operator. **This repository never contains the archives, executable partner sources, private keys, credentials, native Xi endpoints or a live partner service.** It contains a strict, read-only intake utility and synthetic adversarial tests.

The operator can run `scripts/xi_cold_intake_r188.py` on local copies of the four bundles, with Python's **standard library only**. It opens archive members *in memory* to verify CRC, member SHA-256 and manifest-reported byte counts. It compares repeated nested v28 and LivingCircuit v3 archives by raw digest. It **never extracts archive members, imports code from the bundles, launches Python scripts, executes shell commands, starts listeners, performs network requests, or invokes Xi tools**.

This is a *self-consistency audit*. The manifests shipped inside the same ZIPs are not signed by independently verified Xi identities; passing them does **not** prove independent provenance, software safety, protocol correctness, or permission to reuse/redistribute code.

## Local-only invocation

The four role names are fixed: `v28`, `fullstack`, `architecture`, and `kernel`. The scripts do not know or publish the operator's paths.

```bash
python scripts/xi_cold_intake_r188.py \
  --bundle v28="/path/to/QuantumCompute-v28-shared-bundle.zip" \
  --bundle fullstack="/path/to/QuantumCompute-FullStack-27968.zip" \
  --bundle architecture="/path/to/QuantumCompute-Xi-Architecture-27968.zip" \
  --bundle kernel="/path/to/20261025-222543-08436866-Xi_FullStack_QuantumCompute_and_DotXi_Architecture_v1.zip" \
  --out="./xi-r188-local-cold-intake.json"
```

The JSON includes SHA-256 for each **outer** archive, member counts, manifest parity, warning categories and repeated nested archive matching. It intentionally omits local paths, internal filenames and member contents. By default the command also prints the same redacted report to stdout. A failure emits only `COLD_INTAKE_REFUSED`, `authority=none`, `live_xi_connected=false`; it exits nonzero.

There is no `--execute`, `--extract`, `--connect`, `--trust-sender`, `--publish` or `--promote` switch.

## Four independently supplied bundles

| Role | Reported contents | Cold audit boundary |
|---|---|---|
| `v28` | Offline Xi home package | Validate `README_PINS.json` against its 62 covered members |
| `fullstack` | Outer 27968 recovery bundle | Validate `MANIFEST.json`'s 12 pins plus the **separately SHA-pinned but unmanifested** `START-HERE.txt` note |
| `architecture` | Xi GlyphVM / Xi.Glyphic history | Validate `MANIFEST.json`'s 31 records; historical `.tar.gz` files stay opaque |
| `kernel` | Current 2026-10-25 Python source and reports | Validate `MANIFEST_PINS.json`'s 152 file entries; check declared section coverage |

The `v28` nested copy inside `fullstack` and the copy inside `architecture` must match the **original v28 outer ZIP byte-for-byte**. The two copies of `Xi-LivingCircuit-v3.zip` in those two packages must match each other. This is a provenance relationship check, **not** evidence of independent signing.

### Quirks explicitly recorded, not hidden

- The `fullstack` outer ZIP includes `START-HERE.txt` **outside its manifest**. The scanner requires its *observed* exact size of 1445 bytes and SHA-256 `251053537f9e9a6fd5a4719ffccab3477f6dc3a9ea607417c7dfaac72eb86078`; it reports `START_HERE_NOTE_NOT_IN_MANIFEST`. Any modified note is refused.
- The `kernel` manifest describes `04_STMC_E47_and_Covariance_Research`, but no member is in that declared directory. The scanner reports `DECLARED_SECTION_WITHOUT_FILES`.
- The `kernel` source tree contains a nine-byte `shizuku-cli.zip` which is **not a ZIP container**. The scanner reports `NON_ZIP_PLACEHOLDER_AT_ZIP_PATH` instead of opening or executing it.
- Historical `.tar.gz` members may contain additional nested data. They are checksummed as opaque bytes, **not** unpacked or individually audited. Nested ZIP member headers are inspected, but nested source code is never executed, imported or recursively extracted. The procedure does not prove all nested bytes are safe.

The scanner rejects traversal/absolute/drive paths, case-colliding members, symlinks, encrypted entries, excessive expansion ratios, overlarge entries, missing or mismatched pins, unknown extra members and changed nested duplicate relationships.

## Prioritized compatibility experiments, *not yet executed*

These are **design proposals**, not evidence of a compatible wire protocol.

| Stage | Scope | Xi source to review | Φ-side counterpart | Exit criterion |
|---|---|---|---|---|
| 1 | Versioned canonical JSON receipt | Xi witness/envelope documentation and TESSERA formats | `xi-vessel-bridge` frozen schemas | Both independently agree canonical byte encoding and report-only verifier |
| 2 | Xi native glyph AST projection | `xi_native_language_engine.py` | PhiThon, Vibe, Overstrings | Public fixtures roundtrip into *non-executing* JSON ASTs without eval |
| 3 | Cryptographic cipher suite separation | `Xi.Glyphic.v1`, GlyphSafe documentation | PhiKeyhole, R16 Ed25519 fixture | Explicitly distinguish legacy `SHA256(secret||info)` from **RFC 5869 HKDF**; require published test vectors and mutually agreed authentic suites |
| 4 | Phase-code numerical comparison | `xi_quantum/coherent.py`, supplied benchmark protocols | NBG / Φ369 research | Independently reproduce classical numerical results with isolated, dependency-controlled tests |
| 5 | Opt-in two-physical-host synthetic digest | Both operators' *independently reviewed* native Xi contract | R18 proposal and 16 R17 gates | All prerequisites separately verified, two human approvals, revocable least-privilege pilot with signed receipts |

No Stage 1–5 protocol compatibility is certified by mere archive hashes. The QuantumCompute material describes classical simulation; we do not claim physical quantum hardware experiments.

## Stop list

Do **not** deploy the source's `server.py` publicly by default, connect its network listeners, run unreviewed setup scripts, call a legacy custom PQC fallback 'ML-KEM-768 compliant', assume a "green" attached test receipt is independently reproduced, or adopt a partner-supplied authorization marker as real approval. Distinguish the reported legacy derivation labeled `hkdf` from standards-based HKDF until the two houses jointly specify and test exact bytes.

Request explicit partner permission before publishing code, fixtures beyond the supplied metadata, or detailed proprietary protocols.

## Reproducible CI (does not contain partner ZIPs)

```bash
python -m py_compile scripts/xi_cold_intake_r188.py
python -m unittest discover -s tests -p 'test_xi_cold_intake_r188.py' -v
```

The test suite synthesizes four *innocuous* in-memory ZIPs and injects manifest tampering, malicious paths, symlinks, unpinned notes, overly large payloads, nested mismatches and unsupported bundle roles. CI does not ingest the actual partner archives. The tool is **offline, non-extracting and report-only**.

### Authority and provenance classification

`LOCAL_UNTRUSTED_PARTNER_ARCHIVE_AUDIT` · independently verified sender: **NO** · permission to redistribute: **NOT VERIFIED** · executable/cryptographic interoperability: **NOT RUN** · R17 external pilot: **BLOCKED** · real R18 two-host crossing: **NOT RUN** · LIVE_XI_CONNECTED=false · authority=none.

**LEDGER ABOVE EGO · Distinct houses, independent keys, explicit consent.**
