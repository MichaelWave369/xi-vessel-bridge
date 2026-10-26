# R18.6 · Bilateral Pilot Readiness Board

**Classification: PHI_PROPOSED_DISCUSSION_ORDER_ONLY.** R18.6 groups the *unchanged* 16 missing external readiness gates from the canonical `roadmap/bridge-roadmap.json` into four suggested discussion phases, without creating an alternate approval ledger or suggesting Xi has consented.

The seventh Commons Gateway doorway `/gates.html` is a public static, offline-capable **readiness review agenda builder**.

## Four phases (PHI proposed, not Xi approved)

**1. Scope and people:** native protocol contract, out-of-band identity verification, separate human approval, consent, least privilege, and nonsecret human-data scope.

**2. Secure control:** verified transport, bilateral kill switches, provenance, and sovereign independence.

**3. Independent field evidence:** synthetic two-host crossing, durable receipts, negative controls, and exact capsule-byte integrity.

**4. Revocation and recovery:** independent live revocation drills and disaster recovery.

All 16 IDs are the canonical current roadmap gates, and each appears exactly once. The order expresses a *proposal for conversation*, not an executable dependency solver or readiness scoring system. The board reads source states directly from `bridge-roadmap.json`. If a status is promoted, a gate changes unexpectedly, a field is missing, or a new unreviewed gate appears, the board refuses to render rather than silently claiming progress.

## Workflow

Select proposed discussion topics. **Select Phase 1 topics** chooses an initial six-gate conversation; otherwise tick whichever topics matter. You may manually **Copy public agenda** or **Download public agenda JSON**. Both outputs are generated entirely on your device and explicitly say they are unapproved, public-only discussion requests. Selection isn't stored in localStorage, a remote API, a database, an operator's permission ledger, or GitHub. Clearing selection does not alter anyone's status.

The JSON schema `PhiXi.R18_6_PublicDiscussionAgenda.v1` reports `externally_verified_gates=0`, `external_gates_remaining=16`, `approved_operations=0`, `live_xi_connected=false`, `authority=none`, R17 external `BLOCKED` and R18 real two-host `NOT_RUN`. It has no secret, identity token, private URL or signature field. The text agenda is derived only from source roadmap `requirement` and `owner` strings.

This tool is a **companion** to R18.5's concise Xi Room handoff, R17's shared roadmap, and R17.2's candidate intake workbench. It does not duplicate or modify partner intake, issue a native Xi operation, claim proof of identity, or bypass the Xi Room session cap.

## Security

Same-origin GET request only for the already-public `bridge-roadmap.json`, with CSP `connect-src 'self'`. No Xi calls, uploads, private-file inputs, form submissions, persistent storage, arbitrary HTML, or credentials. The service worker precaches only the four new public gate-board files and the existing source roadmap.

## Tests

```sh
node --check roadmap/gates-core.js
node --check roadmap/gates.js
node --test tests/test_gate_board_r186.cjs
python -m unittest discover -s tests -p 'test_gate_board_r186.py' -v
python scripts/build_commons_gateway.py --out dist
```

Node checks ensure the 16 missing canonical source IDs map exactly once, reject live/promotion/unknown gate claims, and prevent any generated agenda from being presented as approval. Python checks the offline bundle and deterministic build. After merge, the Pages deployment verifier must find all four static gate-board assets over public HTTPS before this new page can be called live.

**R17 external pilot BLOCKED · R18 actual two-physical-host crossing NOT RUN · LIVE_XI_CONNECTED=false.**

**Ledger Above Ego. Two houses retain independent keys.**
