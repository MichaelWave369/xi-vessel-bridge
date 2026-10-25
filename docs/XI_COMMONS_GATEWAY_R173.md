# R17.3: Xi ⇄ PHI369 Sovereign Commons Gateway

**PHI-side public publishing infrastructure only. `LIVE_XI_CONNECTED=false`. No remote Xi transport or authorization is enabled.**

R17.3 unifies the already-merged R17 roadmap, R17.1 capability preview registry, R17.2 browser intake, and R18 *synthetic-only* preparatory packet into one polished, offline-capable static site.

## What's inside

| Page / artifact | Source | Published path |
|---|---|---|
| Sovereign Commons Gateway | `roadmap/commons.html` | `/index.html` |
| Evidence roadmap | `roadmap/index.html` | `/roadmap.html` |
| Xi capability preview registry | `roadmap/capabilities.html` | `/capabilities.html` |
| Partner intake workbench | `roadmap/intake.html` | `/intake.html` |
| Source-bound roadmap and registry | `roadmap/*.json` | `/bridge-roadmap.json`, `/capability-registry.json` |
| Public synthetic request + R18 kit | Derived by `scripts/build_commons_gateway.py` | `/handoff/*.json` |
| Offline cache and web manifest | `roadmap/sw.template.js`, `roadmap/manifest.webmanifest` | `/sw.js`, `/manifest.webmanifest` |

This website does not call any external Xi endpoint; the only fetches it makes are for same-origin static JSON and files. Links to Xi and GitHub are user-clicked. Nothing executes untrusted partner scripts, publishes private credentials or creates an admin key. All data from Hunter's side remains **candidate evidence until independently reviewed**.

### Launch locally with no account or deploy keys

From the repository root:

```sh
python scripts/build_commons_gateway.py --out dist
python -m http.server 8000 --directory dist --bind 127.0.0.1
# Open http://127.0.0.1:8000/
```

The site uses relative paths everywhere so the exact same bundle works at a root domain, repository subpath and localhost. Every build validates the R17 status, the 13 unnamed public Xi slots, and the four generated files against the existing R17.1/R18 validators before emitting `dist/`.

### GitHub Pages: explicit activation required

The workflow `.github/workflows/pages.yml` **builds on changes merged to `main`** and supports manual `workflow_dispatch`. It **does not publish the site until the operator explicitly opts in**:

1. In the GitHub repository: **Settings → Pages → Build and deployment → Source → GitHub Actions**.
2. In **Settings → Secrets and variables → Actions → Variables**, create `PHI_XI_ENABLE_PAGES` set to `true`. This is a nonsecret feature flag, not a credential.
3. In **Actions → Xi-Phi Commons GitHub Pages**, run **Run workflow** on `main` (or push a permitted source change after activating).
4. Confirm the **deploy** job reports a GitHub Pages URL. Only that successful deployment proves the website is publicly reachable.

The workflow's **build** job can succeed while **deploy** is skipped. Green conformance or a successful Pages build is NOT a live website claim. The URL may follow GitHub's conventional `<user>.github.io/<repo>/` pattern, but it should only be shared as *live* after the deploy step supplies and verifies its actual URL.

The existing Xi Bridge Conformance workflow also builds a preview artifact named `phi-xi-r17-3-public-gateway-preview` with seven-day retention for review, independent of Pages activation. The deployed site contains no GitHub Actions secrets or externally supplied files.

### Offline behavior

The gateway registers a **versioned, same-origin allowlist-only service worker** when visited on HTTPS or localhost. Install precaches the gateway, roadmap, registry, intake scripts, manifest, and four known public handoff JSON files; a failed cache install doesn't claim readiness. Cache version is derived from the complete public static source bytes.

The worker intercepts **only allowlisted same-origin GET** requests and uses network-first with saved cache fallback. It does not intercept arbitrary URLs, external Xi requests, private file inputs, POST/PUT requests, browser downloads outside the list or remote authentication flows. On version change, it deletes **only older caches with its own prefix**. Offline use requires at least one successful connected load, and external GitHub/Xi links remain online-only.

A public site **must not** cache partner handoff uploads or private data. The intake workbench processes local user-supplied file inputs in browser memory and exports an optional, redacted local review. Offline mode is for public reference pages and synthetic packets only.

### Handoff integrity

The builder generates, with fixed types and byte contents:

- `handoff/request.json`: canonical registry-fingerprint-bound partner questionnaire (zero authority).
- `handoff/synthetic-fixture.json`: fixed synthetic bytes and SHA-256.
- `handoff/pilot-preflight-draft.json`: unconfigured, unapproved, digest-only pilot scope.
- `handoff/transcript-template.json`: `not_run`, no receipts.
- `handoff/manifest.json`: exact `size_bytes` and SHA-256 for each of the above, plus provenance and zero-authority markers.

The browser checks packet byte length and SHA-256 against the build manifest before triggering download when WebCrypto is available; CI independently checks exact bytes and validation. Hashes establish integrity against this static manifest, **not** who operates Xi or whether any external exchange is authorized. The manifest and files have the same publisher, so this is not a third-party signature.

### Verification

```sh
python -m unittest discover -s tests -p 'test_commons_gateway_r173.py' -v
python -m unittest discover -s tests -v
node --check roadmap/commons.js
node --check roadmap/sw.template.js
python scripts/build_commons_gateway.py --out dist
```

The gate deliberately preserves `R15`/`R16` as verified **local fixtures**, `R17` as **externally blocked**, and `R18` as **planned**. Public Xi preview counts (13 capabilities, 12 doors) are source-dated and do not represent confirmed remote operation IDs.

**Ledger Above Ego · Capability ≠ Authority · Two houses keep their keys.**
