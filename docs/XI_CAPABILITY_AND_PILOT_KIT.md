# Xi ⇄ PHI369 · R17.1 partner registry and R18 offline pilot kit

**Current stage:** PHI-side preparation complete when tests pass; **no live Xi connection**, external approval, two-host transport, credential exchange, replica, or delegated authority.

This pack is deliberately suitable to share as a **public, nonsecret source** while Hunter's AI team is unavailable. The request is a proposal from PHI, not an acceptance on Xi's behalf.

## What PHI prepared without involving Xi

| File | What it does | Claim limit |
|---|---|---|
| `roadmap/capability-registry.json` | 13 *anonymous, unmapped* Xi preview slots; 3 PHI read-only local candidates | Public showcase count is not a list of approved operations |
| `roadmap/capabilities.html` | Read-only browser registry, linked from the roadmap viewer | Static pages have no remote authority |
| `reference/python/xi_capability_r171.py` | Validates registry; generates an empty partner questionnaire; inspects a candidate-only response | Never grants or authenticates a Xi operation |
| `reference/python/xi_pilot_r18.py` | Builds and verifies a fixed, tiny synthetic capsule; drafts pilot preflight; checks a candidate transcript | Does not transmit anything or verify remote receipts |
| `tests/test_xi_capability_r171.py` and `tests/test_xi_pilot_r18.py` | Adversarial controls for tamper, injected grants, self-asserted approval, foreign URLs, false live states and dishonest evidence | CI verifies local rules, not remote Xi |

`R15`, `R16`, and `R17` remain as originally scoped. The roadmap still describes **R17 as external-pilot blocked** and **R18 as future two-host testing**.

## One-command-from-source handoff generation

From the repo root (Python 3.12+):

```sh
mkdir -p partner-handoff-output
python reference/python/xi_capability_r171.py inspect
python reference/python/xi_capability_r171.py request > partner-handoff-output/request.json
python reference/python/xi_pilot_r18.py fixture > partner-handoff-output/synthetic-fixture.json
python reference/python/xi_pilot_r18.py verify-fixture --file partner-handoff-output/synthetic-fixture.json
python reference/python/xi_pilot_r18.py draft > partner-handoff-output/pilot-preflight-draft.json
python reference/python/xi_pilot_r18.py preflight --file partner-handoff-output/pilot-preflight-draft.json
python reference/python/xi_pilot_r18.py transcript-template > partner-handoff-output/transcript-template.json
```

The outputs contain **no private keys, real identities, account credentials, hidden endpoints or personal data**. GitHub Actions also publishes a short-retention public fixture artifact for the partner handoff once the updated CI workflow succeeds.

```sh
# Both commands MUST refuse a claim that public templates prove live access:
python reference/python/xi_capability_r171.py require-live
python reference/python/xi_pilot_r18.py require-live
# Exit code 2 is expected for each.
```

## Concrete request to Hunter's team

We have an honest 13-slot registry based on the current public Xi community preview count. **We have not copied invented names into it.** Please return, for each capability you want to nominate for a first pilot:

1. Its canonical Xi-authored operation ID, public display name, supported versions, and named source maintainer.
2. A human-readable nonsecret transport/endpoint **description**, exact source-backed schema bytes or an independently checkable SHA-256, and proof of which code publishes that interface.
3. The least-privileged read-only operation, input/output shape, expected error statuses, identity/room binding, duplicate/replay behavior and independent revocation flow.
4. Explicit separation of public discovery, authenticated peer identity, independently approved request scope, and proof of real runtime execution.
5. Whether `artifact.sha256`, native capsule verification, or Tessera grammar discovery should be the **first tiny synthetic-only candidate**.

**Do not send private keys, API tokens, passwords, bearer credentials or private session URLs** with the response. The official source of an interface must be independently confirmed. Source acknowledgments are not human consent; written operator approvals are still required separately.

The machine-generated `request.json` carries an exact SHA-256 fingerprint of the registry it is replying to. A response should use `PhiXi.PartnerCapabilityResponse.Candidate.v1`, containing only `schema`, `reply_to_registry_sha256`, `statement`, and `records`. Each record uses **only**:

```json
{
  "slot_id": "xi-preview-01",
  "name": "example-CANDIDATE-only",
  "operation": "candidate.read",
  "schema_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "endpoint_description": "Nonsecret narrative only, not a live credential",
  "evidence_url": "https://www.xi-field.com/#community",
  "source_author": "Submitting maintainer (identity not independently verified)"
}
```

The values above are *fictional format examples*, not actual Xi operations or evidence. The submitted response remains candidate data and may be inspected as follows:

```sh
python reference/python/xi_capability_r171.py inspect-response --response /path/to/response.json
```

Result is **`SELF_REPORTED_CANDIDATES_ONLY`** regardless of how many slots are filled. A separate human and evidence process must decide what is true and authorized.

## R18 pilot kit, ready on PHI's side

The exact synthetic payload is fixed in code; its bytes are printed in base64 and accompanied by a size, SHA-256, source declaration, intended use and explicit `authority:none`. The first real external pilot, if later mutually approved, would exchange **a digest of this synthetic content**, not any GitPorch/NBG/PhiOS private data.

The preflight draft is intentionally non-authorizing. If someone flips `xi_operator_approval` or pastes a `xi_peer_pin`, the inspector labels it **self-reported and unverified** rather than completing the gate. Even a filled document remains blocked without independently authenticated evidence. No address-binding or outbound network commands are provided.

A returned real-world transcript can be reviewed locally with:

```sh
python reference/python/xi_pilot_r18.py inspect-transcript --file /path/to/candidate-transcript.json
```

This only checks structure and claimed SHA-256 matches. It **cannot validate peer identity, which machines were used, or receipts**. A claimed matching transcript is never counted as verified live Xi access.

## Next genuine joint acceptance boundary

An **external** test requires both human operators to approve a unique peer key, explicit room/operation/time and synthetic-only data scope. The receiving host must validate its independently authenticated peer identity, encrypted transport, compatible Xi native schema, durable signed receipts, replay limits and local pause/revoke controls. A separate evidence collector should verify actual two-host transcripts and interruption/revocation tests. **R10–R14 and R17 gate blockers are not bypassed by these templates.**

No credential files, copied third-party runtime, remote services, auto-sync, model invocations, shell commands or repository writes are part of this handoff.

**Ledger Above Ego · Capability ≠ Authority · Both houses keep their keys.**
