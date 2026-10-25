# R17.2 · PHI-side Partner Intake Workbench

**Status: local, read-only intake. `LIVE_XI_CONNECTED=false`. No Xi runtime or Hunter machine has participated.**

R17.2 prepares a safe receiving station for a later Xi-side handoff while Hunter's team is offline. The **existing** R17.1 registry and R18 synthetic pilot types remain the only accepted input grammars; third-party archives, executables, private endpoint secrets and live credentials are not needed and must not be loaded.

## Browser workbench (no account, install, or external service)

Open the repo's `roadmap/intake.html` over **localhost** by serving the `roadmap/` directory:

```bash
cd roadmap
python -m http.server 8000 --bind 127.0.0.1
# Open http://127.0.0.1:8000/intake.html
```

The browser downloads `capability-registry.json` **only from its own static origin** and computes its canonical SHA-256. Three local file inputs accept:

| Input | Exact accepted schema | Meaning |
|---|---|---|
| Candidate capability response | `PhiXi.PartnerCapabilityResponse.Candidate.v1` | Self-reported proposals mapped to up to 13 slots; zero grants |
| Pilot preflight | `PhiXi.R18PilotDraft.v1` | Claims awaiting independent evidence; never authorization |
| Synthetic pilot transcript | `PhiXi.R18TranscriptCandidate.v1` | Self-reported checks and receipt references, not a real two-host proof |

The `Load fictional example` control exercises all three formats without any Xi files. `Clear review` discards imported data and clears file inputs. `Export redacted JSON report` creates a local download containing only hashes, slot IDs, candidate counts and unresolved gate descriptions. No source author statements, operations, endpoint details or raw input bytes enter the exported report. Imported bytes exist only in the current browser's memory; no backend uploads or analytics are implemented.

The page's Content Security Policy prevents remote scripts, remote resource loading and forms. External source links are ordinary, user-clicked navigation, never automatic fetches. Serve over a local HTTP origin because browsers generally restrict reading companion files and WebCrypto from `file://`.

**Review limits:** the UI is a convenient preflight/syntax check and does *not* cryptographically authenticate an Xi identity, independently verify native schema content, confirm receipt signers, or grant access. A matching SHA-256 is only byte agreement with a submitted claim; it is not identity or authorization proof.

## Equivalent offline Python inspector

Requires Python 3.12+, with no extra dependencies for this inspector:

```bash
python reference/python/xi_partner_r172_workbench.py
python reference/python/xi_partner_r172_workbench.py \
    --response /path/to/candidate-response.json \
    --preflight /path/to/pilot-preflight-draft.json \
    --transcript /path/to/transcript-candidate.json
```

The CLI accepts files up to 128 KiB, uses the R17.1 and R18 validators, reports exact **raw file byte SHA-256** for forensic comparison, and prints a **redacted** review to stdout. The Python registry digest uses sorted-key compact canonical JSON. The JS browser also computes that canonical digest (with sorted ASCII JSON keys), then hashes each supplied source file's exact bytes.

The following check is expected to fail with exit code **2**:

```bash
python reference/python/xi_partner_r172_workbench.py --require-live
```

No response content, credentials, source free text, or potential server URLs are copied into CLI error reports. A malformed or unauthorized envelope is refused rather than automatically repaired, interpreted as an instruction, or promoted to a verified capability.

## Verification and CI

```bash
python -m unittest discover -s tests -p 'test_xi_partner_r172_workbench.py' -v
node --test tests/test_intake_core.cjs
node --check roadmap/intake-core.js
node --check roadmap/intake.js
python -m unittest discover -s tests -v
```

The Node tests exercise **the actual browser intake validator** with malformed and adversarial records. Both runtime suites reject forged scope, unapproved host URLs, duplicated slots, self-asserted approvals, forged live states, tampered registry bindings, and not-run transcripts with invented host evidence.

## Decision ownership and later R18 crossing

All R17/R18 external gates remain **blocked** until **both humans** independently approve exact identity pins, native schema bytes, scopes, encrypted transport, receipt checks and pause/revoke controls. Hunter's crew can submit candidate JSON later; their response is not a tool call, access grant or signature from a confirmed identity. No external server code, SSH, WebSocket, credential provisioning, mirroring or cross-machine pilot is activated here.

**Ledger Above Ego. Sovereign houses. Inspect first; authorize separately.**
