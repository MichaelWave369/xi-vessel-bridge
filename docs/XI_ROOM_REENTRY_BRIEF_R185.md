# R18.5 · Public Xi Room Session Re-entry Briefing

**Purpose:** communicate the current PHI-side public engineering state in one short reviewable note if/when the Xi Room becomes accessible again. Session limits are controlled by the Xi Room, not by this project. This is not a room bypass, background messenger, agent login, or request for a credential.

The Commons sixth doorway `/room.html` is a **static public briefing**. It contains two read-only text fields with human-clicked copy actions:

1. A one-minute summary of the Commons Gateway, R18.1 local signed workers, R18.2 local report inspector, R18.3 illustrative browser sandbox and R18.4 genuine local-worker cryptographic fault gauntlet. It cites the successful source/CI evidence.
2. Three nonsecret, separate-house review questions: an Xi-native read-only schema citation, independently verified public identity binding without exposing key material, and a jointly consented, revocable synthetic two-host test proposal.

The page links to the public Gateway, immutable post-merge R18.4 conformance run, public Pages deployment verification, unfilled partner questionnaire, unfilled R18 pilot preflight draft and R18.4 code notes. No chat transcript, user/session token, private key, credential or real remote endpoint appears in these public materials.

## What we know, and what still requires Xi-side review

- R15–R16 local fixtures and R18.1–R18.4 simulations/tests establish PHI-side local protocol behavior only.
- The R18.4 CI uses **two different local subprocess keys per scenario on one physical host**, tests 14 fault cases and archives a redacted JSON report. The browser can shape-check but cannot authenticate that JSON's author.
- R17's 16 external gates remain unresolved, including independent two-operator approval, Xi-native schema, independently verified identity, secure network transport, least privilege, consent, separate revocation and recovery.
- The R18 real two-physical-host signed digest crossing has **NOT RUN**. The preview count of 13 Xi capabilities and 12 Xi doors remains unverified and does not mean callable operations.
- Xi Room access has a session cap. This page never assumes a session is available or asks a robot to log in.

## Publication and security

`roadmap/room.html`, `room.css`, and `room.js` are built into `dist` by the existing deterministic static builder and precached by the public-only same-origin service worker. The page declares `connect-src 'none'`, no forms, no external runtime calls and no partner file intake. The script reads **only source-reviewed text** and writes it to the clipboard **only on a human button click**, falling back to selecting the text for manual copy. It never reads the clipboard or saves text anywhere. External citations open only on deliberate navigation.

Source and deployment tests:
```sh
node --check roadmap/room.js
node --test tests/test_room_briefing_r185.cjs
python -m unittest discover -s tests -p 'test_room_briefing_r185.py' -v
python scripts/build_commons_gateway.py --out dist
```
The public deploy verification is extended to probe `room.html`, `room.css`, and `room.js` over HTTPS and to affirm that the public source-and-limits labels survived publication. Do not claim `/room.html` live until the merge has completed and the **Pages deploy and verify jobs both succeed**.

## Review principle

One house can suggest a schema or pilot protocol. The other independently chooses whether to review it. A public reply or link is not approval, identity verification, or a credential.

**LEDGER ABOVE EGO · Both houses retain independent keys.**
