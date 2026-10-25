# R17: Xi ⇄ PHI369 Shared Roadmap and Pilot Readiness

**Status: planning/evidence-intake only. `LIVE_XI_CONNECTED=false`. No external Xi endpoint is accessed.**

The Xi Living Door public community page currently displays **13 bidirectional capability previews** and **12 sovereign-door previews**, with an explicit warning that live crossings are pending. We preserve those figures strictly as a source-dated *public preview count*, not a verified list of 13 APIs, 12 authenticated rooms, or permission to call anything.

Sources:

- [Xi Living Door · community / bridge preview](https://www.xi-field.com/#community)
- [Xi-Vessel-Bridge R15 offline evidence adapter, PR #19](https://github.com/MichaelWave369/xi-vessel-bridge/pull/19)
- [Xi-Vessel-Bridge R16 local signed handshake, PR #20](https://github.com/MichaelWave369/xi-vessel-bridge/pull/20)
- [R16 limitations and external pilot conditions](PHI_XI_HANDSHAKE_R16.md)
- [ForgeCore candidate operations (non-authorizing)](FORGECORE_COMPATIBILITY.md)

## Two artifacts, one source of truth

- `roadmap/bridge-roadmap.json`: source-dated public counts, proposed milestone dependencies, capability candidates, and all 16 pilot gates. Never put private endpoints or credentials here.
- `roadmap/index.html`: a standalone zero-dependency, read-only interface that fetches the JSON from its own directory. It does not connect to Xi, mutate grants, phone home or call GitHub APIs.
- `reference/python/xi_shared_roadmap_r17.py`: a fail-closed JSON inspector checking statuses and core governance boundaries. It refuses false live claims; **it does not verify a partner's identity or external runtime**.

Run the inspector from the repository root:

```bash
python reference/python/xi_shared_roadmap_r17.py
python -m unittest discover -s tests -p 'test_xi_shared_roadmap_r17.py' -v
```

To verify that a static roadmap **cannot** authorize a crossing:

```bash
python reference/python/xi_shared_roadmap_r17.py --require-live
# expected exit code 2, with R17_REFUSED
```

For the browser interface, from the repository root:

```bash
cd roadmap
python -m http.server 8000 --bind 127.0.0.1
# Open http://127.0.0.1:8000/ in your browser.
```

This repo does **not** claim that a GitHub Pages deployment is configured. Deploying the static roadmap is a separate operator decision. Source links and counts must be re-reviewed if the upstream Xi showcase changes.

## Evidence-based milestone ladder

| Rung | Current category | What is established |
|---|---|---|
| R15 | local fixture verified | Offline bundle/intake inventory and signed relay inspection with no remote actions |
| R16 | local fixture verified | Two-process loopback Ed25519 challenge/proof/receipt and SQLite replay denial, pause/revoke |
| R17 | **blocked** | External schema, independent peer pins, two-human review and transport/consent controls are not yet established |
| R18 | planned | Two-host *synthetic-digest-only* encrypted and authenticated crossing, independent receipts and negative controls |
| R19 | planned | Bounded opt-in read-only capsule transfer with byte identity and provenance |
| R20 | planned | Human-approved independent offline recovery drills, neither house becoming a single point of failure |

The R17 JSON gate roster is a **proposal created for this project**, not a copy of a mutually approved Hunter roadmap. It requires both operators to inspect and agree to the precise terms. All 16 gates remain `missing` in the current snapshot, and merely editing them to `candidate_unverified` still blocks live status.

## Potential workstreams (not verified Xi capability names)

1. **Transport and provenance**: Build an exact-byte signed receipt path with explicit key pins and a pre-agreed native Xi `xi.exchange.v1` packet mapping.
2. **PhiOS / GitPorch / PhiARK**: Inspect only operator-curated, nonsecret exports. No ambient filesystem sharing or automatic mirror promotion.
3. **Super Φ.Vessel / ForgeCore**: Capability discovery before privileged requests. `artifact.sha256` stays the initial reference fixture, while ForgeCore capsule verification and grammar discovery are candidate operations rather than agreed bridge aliases.
4. **NBG / Keyhole**: Compare provenance and reversible memory boundaries via synthetic fixtures; no sharing of private memories or model state by default.
5. **FieldAtlas / Infinite Porch / XR**: Cross-link publicly available doors and project pages; public navigation does not imply a private room grant.

The first action for a real external pilot is a jointly reviewed **candidate contract** describing exact Xi/Phi identities, endpoint scheme, packet/schema bytes, capabilities, cryptographic transport and operator pause/revoke procedure. R10–R14 already supply conservative contract/evidence exercises. R17 does not weaken or bypass any of them.

## Claim discipline and contributions

- **Public preview**: What Xi's site displays; content and counts may change.
- **Local fixture**: Tested inside our own CI, with synthetic identities and loopback networking only.
- **Candidate**: A possible independent peer feature awaiting authentic contract, operator consent and actual runtime evidence.
- **Externally verified**: Not represented by this static roadmap; requires a separately reviewed, authenticated real crossing.
- **Production**: Not authorized. A successful proof is not a permission to run tools or share data.

Submit edits to the JSON and docs through pull requests with source links. Keep status as blocked until a later, independently approved protocol expands the evidence verification rules. Both operators must have an immediate local stop. All third-party research and software retain their own authorship.

**Two houses, independent keys, one auditable roadmap.**
