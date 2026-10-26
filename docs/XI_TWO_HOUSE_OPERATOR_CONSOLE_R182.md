# R18.2 · Two-House Operator Console

**Classification:** `PUBLIC_STATIC_REVIEW_CONSOLE`. This is an offline-capable inspection UI for R18.1's two-process local-only simulation. **NOT** a live Xi remote controller, a cryptographic verifier of outside identities, a protocol command sender, or an operator approval authority.

## Open in the public Commons Gateway

Once this PR is merged, the GitHub Pages workflow builds and verifies:

`https://michaelwave369.github.io/xi-vessel-bridge/lab.html`

The Gateway home also gains a fourth **Two-House Lab** doorway beside Roadmap, Capability Registry and Partner Intake. The console and its illustrative source-defined preview are precached by the existing service worker after a successful first online visit. On localhost:

```sh
python scripts/build_commons_gateway.py --out dist
python -m http.server 8000 --directory dist --bind 127.0.0.1
# http://127.0.0.1:8000/lab.html
```

Static assets are `roadmap/lab.html`, `lab.css`, `lab.js`, and `lab-core.js`, with `dist/lab-preview.json` **generated at build time** from a source-controlled *illustrative* summary contract.

## Two ways to inspect

1. **Load illustrative lab preview**: fetches a small same-origin JSON preview containing the expected R18.1 summary shape. It is explicitly `preview_only: true`, `illustrative_fixture_not_fresh_run`. The UI labels every control **illustrative**, not a newly executed test or a remotely supplied witness.
2. **Import a local R18.1 report**: use a JSON report produced by `python reference/python/xi_two_house_r181.py demo` or download the redacted `phi-xi-r18-1-two-house-local-simulation` CI artifact from <https://github.com/MichaelWave369/xi-vessel-bridge/actions/runs/40248847400>. The file must be UTF-8 JSON of at most 16 KiB. The browser reads the bytes via `File.arrayBuffer`, requires exactly the known summary fields and types, then computes SHA-256 locally with WebCrypto. Nothing is posted to a server, entered into local storage, installed, signed or used to issue permissions.

A compatible imported report is labeled **untrusted local file / shape valid**, never independent evidence of who authored it. This is not a general-purpose JSON or partner-transcript viewer. Unknown fields, secret fields, changed payload hashes, claimed additional hosts, nonlocal transport, new permissions, forged live status or a different R18.1 result are refused. The browser intentionally does **not** attempt to verify Ed25519 signed protocol messages; those are held inside R18.1's Python lab, not exposed to this public website.

The seven Boolean controls represented in the report are independent ephemeral keys, bilateral R16 handshake, signed synthetic digest roundtrip, bidirectional digest checks, durable replay denial after restart, unilateral local pause, and durable local revocation. They are **claims in the selected JSON**; the provenance labels reflect that. Running tests is an explicit Python/CI action, not a browser button.

The separate read-only **16 external pilot gates** are loaded from the bundled `bridge-roadmap.json`. All remain `missing` or `candidate_unverified`; a local lab cannot promote any gate. A source version change that violates the known roadmap grammar fails closed.

## Export policy

The **Download redacted review** button emits only:

- a new review schema `PhiXi.R18_2_LocalLabReview.v1`;
- whether the input was an illustrative preview or an untrusted locally imported summary;
- SHA-256 of the original input bytes;
- seven known summary control IDs (reported, not verified);
- process count 2, physical host count 1, outstanding external gate count;
- zero authenticated Xi receipts, zero externally promoted gates, `live_xi_connected: false`, `authority: none`, R17 `BLOCKED` and R18 real two-host `NOT_RUN`.

No original file name, raw JSON, signed envelope, key, public-key identifier, receipt body, timestamp, private path or session identifier is exported. A hash binds the review only to locally selected bytes, not to an authenticated identity.

The page uses source-local JS/CSS only, strict CSP, `textContent` for untrusted labels, and no background sync, third-party analytics, browser local storage, iframe, server action, network listener or Xi API. External GitHub links are user-clicked only. Only static same-origin files are precached; imported reports are never cached.

## Validation and verified publication

```sh
python -m pip install -r requirements-r3.txt
python -m unittest discover -s tests -p 'test_lab_console_r182.py' -v
node --test tests/test_lab_core_r182.cjs
python scripts/build_commons_gateway.py --out dist
```

The Python integration tests compare the illustrative preview's entire `witness` object against an **actual fresh R18.1 demo run**. Node tests reject forged authority and malformed reports, enforce redacted export, check that the source roadmap's 16 external gates remain unpromoted, and verify that imported bytes do not leave the browser. The existing GitHub Pages verifier now probes and checks the published `lab.html`, JS files, preview provenance and the exact built preview SHA-256. Until the **deploy + verify** jobs both pass after merge, the new URL is only an anticipated destination.

## Still blocked: actual Xi field pilot

R18.1 and R18.2 do not bind any peer key to Hunter, authenticate ForgeCore as a real Xi peer, establish an encrypted independent two-host transport, obtain mutual human consent, or issue remote permissions. The public website's existence proves none of those things. R17 external gates remain **BLOCKED**. R18 **real two-host crossing NOT RUN**.

**Ledger Above Ego · Two houses. Independent keys. No authority from a dashboard.**
