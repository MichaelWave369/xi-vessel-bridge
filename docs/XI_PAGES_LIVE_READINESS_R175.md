# R17.5 · Verified public Commons Gateway publication

**This milestone checks public website availability, not a live Xi system.**

## Activation: one owner setting, no credentials

The existing R17.3 GitHub Pages workflow compiled a complete public-only gateway but deliberately skipped its deployment unless a repository variable was created. R17.5 removes that extra variable and instead detects GitHub's actual Pages publishing source.

To authorize publishing, open this repository's **Settings → Pages → Build and deployment → Source** and choose **GitHub Actions**. This is the only settings change required.

Then use **Actions → Xi-Phi Commons GitHub Pages → Run workflow → main** (or merge a change included in the workflow's `main` paths). A `detect-pages` job checks the repository's Pages setting with GitHub's own API:

- If the repository is **not yet configured for GitHub Actions**, build proceeds and the deploy job is **skipped**. The workflow summary explains the one-time setting.
- If Pages source is **GitHub Actions**, deploy runs with the scoped standard `GITHUB_TOKEN` Pages/OIDC permissions, and **no new PAT or account credentials**.
- Unexpected Pages API errors fail detection instead of pretending that the site is configured.

Once deployed, the final `verify` job checks the actual public HTTPS origin:

`https://michaelwave369.github.io/xi-vessel-bridge/`

This is a **candidate URL until a successful deploy and verification job**. Don't promote any external entry to a confirmed live website before that.

## What the public verification proves

The `scripts/verify_commons_deployment.py` verifier is deliberately limited to the exact canonical HTTPS GitHub Pages origin and repository path. It checks:

1. A live response containing the Gateway's own landing-page claims.
2. The public, zero-authority synthetic manifest.
3. A 13-slot, unverified/non-authorizing registry whose fingerprint matches the manifest.
4. The existing roadmap and offline partner intake pages.
5. The generated versioned public service worker.
6. All **four** synthetic handoff packets, byte-for-byte against exact sizes and SHA-256 digests in the public manifest.

The verifier also compares the **deployed manifest SHA-256** with one independently rebuilt from the same checked-out source revision. It retries briefly for CDN propagation. A successful run publishes a `phi-xi-r17-5-pages-availability-evidence` Actions artifact containing only public URL, file fingerprints and verification category.

**A passing verification establishes that the public *static files* are reachable and match source. It does not authenticate Hunter, authorize a user or agent, prove a trusted remote protocol endpoint, or change R17/R18 readiness.**

## Local test

```sh
python -m unittest discover -s tests -p 'test_commons_deployment_r175.py' -v
python -m unittest discover -s tests -v
```

The self-contained tests build the public site in a temporary directory and simulate network file retrieval. They reject an incorrect origin, spoofed landing page, wrong expected manifest, tampered packet bytes, unauthorized registry promotion, and missing assets. Nothing in tests contacts the real network.

A manual real-public-origin check, **only after publishing**, is:

```sh
python scripts/verify_commons_deployment.py \
  --url https://michaelwave369.github.io/xi-vessel-bridge/
```

## Four destination upgrades only after verification

Current source-only references in **Infinite-Commons, FieldAtlas, GitPorch, and PhiOS** are deliberately correct while the Gateway isn't confirmed live. The next PRs may add public website links only after a successful R17.5 `verify` run proves the site is reachable:

| Repo | Planned change | Authority boundary |
|---|---|---|
| Infinite-Commons | Add a user-clicked website link beside the existing canonical GitHub source reference | Not a fifth fictional world, never auto-connect |
| FieldAtlas | Add a reviewed web destination and later a book chapter, with a site verification receipt | No unverified Pages auto-discovery promotion |
| GitPorch | Add a public website URL to the existing source-only evidence shelf | No repo mirror, code sync or live Xi grant |
| PhiOS | Add an external web link to the existing offline-bundled catalog tile | Not installed, not bundled, no launch permission |

The four integration repos do **not** need to claim Xi availability; all can continue showing R17 external BLOCKED and R18 two-host NOT RUN after the public website publishes.

**LEDGER ABOVE EGO · Capability ≠ Authority · Two independent houses keep their keys.**
