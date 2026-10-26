# R18.7 · Public Synthetic Pilot Charter Studio

**Classification:** `UNAPPROVED_PUBLIC_PROPOSAL`. This is a proposal authoring page, **not** an Xi identity authenticator, operator approval form, native transport specification, live deployment, or consent capture mechanism.

## Why it exists

R18.6 groups sixteen missing bilateral gates into a public proposed discussion order. R18.7 goes one step further: it composes a **single narrow and reviewable synthetic pilot charter** from three existing, already governed R18 source packets:

- `handoff/synthetic-fixture.json`: exact **88-byte public fixture** from `reference/python/xi_pilot_r18.py`, pinned by SHA-256 `8370bdb1f706a2168accc1c225a37c98ec907cd3e954b67c1cdcc9d8ddd8feb5`.
- `handoff/pilot-preflight-draft.json`: original `PhiXi.R18PilotDraft.v1` with no peer pins, endpoints, native schema or human approvals, and transport `unconfigured`.
- `bridge-roadmap.json`: 16 missing external gates, R17 `blocked` and real R18 `planned`.

The browser refuses generation if any source claims a verified external gate, promoted milestone, configured transport, human approval, altered fixture content, widened scope or unexpected fields. In contrast to a newly invented handshake contract, this is an **unapproved proposal envelope around the existing R18 source**.

## What the page does

The eighth Gateway doorway, `/charter.html`, offers two candidate discussion scopes:

1. **Single synthetic digest only**: propose `artifact.sha256` of exactly the existing 88 public bytes.
2. **Digest plus proposed negative controls**: the same digest, plus a *candidate review list* of thirteen additional fault conditions. These are questions for independently authorized future testing, **not** execution rights or claims of Xi-native semantics.

Both produce the same hard constraints: `read_only=true`, `dry_run_only=true`, `data_classification=synthetic_public`, `max_payload_bytes=88`, `peer_data_included=false`; zero approvals, zero authenticated operators, zero authorized operations, no transport or endpoint, and 16 missing gates.

The five proposed review phases are independent preparation, verified identity/transport, two human go/no-go decisions, **one** synthetic digest only if genuinely authorized outside this tool, and unilateral revoke/disconnect. The document includes stop conditions for missing consent, unverified identity/schema, expired or replayed requests, unexpected data or scope, bad receipts, or either house revoking.

The UI provides a textual source-qualified draft preview, a user-click-only **Copy short room proposal** button, and **Download unapproved charter JSON**. Nothing is sent to the Xi Room, posted to a server, stored locally, signed, or passed into a runtime launcher. No private key, endpoint, account credential, personal data, or operator name can be entered or exported.

## Machine-readable schema and evidence boundary

The new client-side output schema is `PhiXi.R18_7_ProposedSyntheticPilotCharter.v1`, with **status `UNAPPROVED_PUBLIC_PROPOSAL` and classification `SYNTHETIC_PUBLIC_CANDIDATE_NOT_EXECUTABLE`**. It is for conversation only. It is **not a revision of** `PhiXi.R18PilotDraft.v1`; the latter stays immutable, sourced from the existing Python contract.

`roadmap/charter-core.js` enforces exact key sets, frozen scope values, the original source fixture and no privileged state in its export validator. The two draft variants differ only in lists of **proposed** negative controls. The document cannot be submitted directly to a real bridge or be treated as a valid peer-signed receipt.

A downloaded charter is an unsigned self-reported file. Even if its shape passes every static validator, that is **not** independent evidence of any Xi operator's identity, consent, native schema, encrypted transport, receipt or live crossing. External gate `identity`, `native_contract`, `two_operator_approval` and fourteen other external conditions remain missing.

## Static publication and offline privacy

The page reads exactly three **same-origin public** JSON files via GET, with CSP `connect-src 'self'`. No third-party scripts or APIs, no Xi endpoint, no local file imports, no background upload, no localStorage or form submits. JavaScript only generates a preview and downloadable public JSON in the current browser memory. The service worker caches the four public UI files and the existing source fixtures after initial online visitation.

The existing Pages workflow independently probes `charter.html`, `charter.css`, `charter.js` and `charter-core.js` on the actual GitHub Pages HTTPS origin. Do not call the new page live until the PR merges and Pages **deploy + verify** jobs both succeed.

## Reproduce the checks

```sh
python -m pip install -r requirements-r3.txt
node --check roadmap/charter-core.js
node --check roadmap/charter.js
node --test tests/test_charter_core_r187.cjs
python -m unittest discover -s tests -p 'test_charter_bundle_r187.py' -v
python scripts/build_commons_gateway.py --out dist
```

Node negative controls deliberately inject malformed source fixtures, arbitrary remote endpoint strings, pretend human approvals, elevated operations, false pilot completions, nonpublic data classification, duplicate gates, bad digest bytes and unknown fields. Python checks that the published fixture and preflight are **exactly equal to outputs from the original R18 Python implementation**, and the offline build is deterministic.

**R17 external pilot: BLOCKED · Real R18 two-host: NOT RUN · Live Xi: NOT CONNECTED · Authority: none.**

**LEDGER ABOVE EGO. Two houses. Two independent yes/no decisions.**
