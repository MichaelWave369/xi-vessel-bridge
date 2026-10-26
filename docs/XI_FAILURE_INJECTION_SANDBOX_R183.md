# R18.3 · Two-House Failure-Injection Sandbox

**Classification: ILLUSTRATIVE_DETERMINISTIC_BROWSER_SIMULATION.** This is an in-memory, browser-only teaching tool. It does NOT execute Python workers, generate or verify Ed25519 signatures, contact Hunter or Xi, approve requests, change a real revocation ledger, or operate between hosts.

## Public entry and offline support

Once the Pages deployment and public verifier succeed, the new destination is https://michaelwave369.github.io/xi-vessel-bridge/fault.html. Reach it from the fifth Commons Gateway doorway or the R18.2 Operator Console. It is precached by the existing allowlist-only public service worker after the first online visit.

## What this simulates

The deterministic state machine models one PHI-sim requester and one Xi-sim receiver, with a fixed synthetic digest, abstract identity pins and signature-validity flag, session, timeout, independent permission allowlist, pause/revocation flags and a durable consumed-request-ID model. The abstract signature flag is NOT a cryptographic check. No real process, host, network or key material participates.

The fourteen fixed scenarios are: baseline permitted digest, unpinned sender, wrong recipient, tampered signed-byte flag, expired request, wrong session, repository-write scope escalation, receiver without permission, local pause, revocation, duplicate request ID, replay after simulated restart, tampered response receipt, and a committed request whose response was lost before a duplicate retry.

The UI exposes one-case, run-all, reset and redacted export controls. It displays each abstract house's decision sequence, the expected policy outcome, the observed illustrative verdict and the number of simulated commits. The exported JSON contains only fixed scenario IDs, outcomes, commit counts, labels and explicitly zero external authority. No private key, signer, signature, raw packet, session identifier or credential enters any export.

## How the three labs differ

- R18.1 actually runs TWO local Python OS processes, with temporary Ed25519 fixture keys and independent SQLite ledgers. Its proof applies to this local fixture, not a real Xi pilot.
- R18.2 validates shape and views redacted R18.1 results but cannot authenticate the source of imported JSON.
- R18.3 merely illustrates expected fail-closed behavior with a deterministic JavaScript state machine. Green R18.3 tests establish model consistency only, not cryptographic correctness of another implementation or new independent partner evidence.

The page uses a CSP of connect-src none, worker-src none and script-src self. It contains no fetch, XHR, WebSocket, remote analytics, private-file inputs, background syncing or persistent client storage. Only explicit user clicks navigate to GitHub or other existing public pages.

## Tests and deployment

Run from the repository root:

    node --check roadmap/fault-core.js
    node --check roadmap/fault.js
    node --test tests/test_fault_core_r183.cjs
    python -m unittest discover -s tests -p 'test_fault_bundle_r183.py' -v
    python scripts/build_commons_gateway.py --out dist
    python -m http.server 8000 --bind 127.0.0.1 --directory dist

Then open http://127.0.0.1:8000/fault.html.

The Node suite checks fourteen decisions, receipt refusal, restart/replay and lost-reply handling, strict redaction and no remote calls. The Python suite checks the offline allowlist, Pages package and security declarations. The post-deploy verifier checks that four public sandbox files actually exist on the verified GitHub Pages host. Until deploy and verify succeed, its proposed URL is not confirmed live.

## Evidence still missing

R17 external pilot remains BLOCKED and the R18 real two-physical-host pilot remains NOT RUN. The sandbox cannot establish real operator identity, mutually authenticated TLS, independent Xi consent, jointly pinned native schemas, pilot receipt signatures, or any external grant.

**LEDGER ABOVE EGO. Capability is never authority.**
