# R18.4 · Real Local-Worker Cryptographic Fault Gauntlet

**Evidence classification: LOCAL_TWO_PROCESS_CRYPTOGRAPHIC_FIXTURE_ONLY.**

R18.4 closes an important distinction: R18.3 models fourteen policy outcomes using a deterministic JavaScript state machine, while R18.4 injects the corresponding faults into **actual local Python R18.1 worker processes** exercising Ed25519 signatures, independent per-house key material, R16 signed mutual handshakes, and SQLite replay protection.

This is deliberately NOT a live Xi/Hunter integration, a two-physical-host experiment, a security audit, or an authority grant.

## Reproduce the cryptographic worker run

From the repository root, with the project's existing Python cryptography dependencies installed:

    python -m pip install -r requirements-r3.txt
    python reference/python/xi_fault_gauntlet_r184.py demo
    python -m unittest discover -s tests -p 'test_xi_fault_gauntlet_r184.py' -v

The CLI creates a temporary directory for each case and starts two OS worker processes named `phi-sim` and `xi-sim`, **both on one physical machine**. Each gets a different newly generated Ed25519 key, independently pinned fixture peer, independent R16 challenge/receipt state, a per-house digest-operation allowlist and a durable SQLite transaction ledger. The coordinator injects mutations via local subprocess stdin/stdout. It opens no sockets or Xi transports and needs no remote permissions.

The fourteen cases are baseline valid digest; wrong pinned sender; signed wrong recipient; actual signed-byte tampering without re-signing; expired signed request; wrong session; correctly signed disallowed repository-write scope; receiver without digest permission; local receiver pause; local receiver revocation; duplicate accepted request ID; replay after receiver restart and re-handshake; tampered signed result receipt (followed by the acceptance of its original valid counterpart); and a deliberately withheld response after a durable commit, followed by a denied duplicate retry.

Only the fixed R18 synthetic artifact digest is allowed. No arbitrary files, external user data, shell commands, model tools, repository writes, identities of real people, or actual Xi operations are exchanged.

**At-most-once behavior:** A signed request is recorded in the receiving worker's SQLite ledger before its response is returned. In the lost-reply case the coordinator discards the response, then retries the already-consumed request ID. The receiver refuses it and the ledger retains exactly one commit. This prioritizes preventing duplicate execution, **not** guaranteeing a response will be delivered.

## Redacted CI evidence and website inspector

The Xi Bridge Conformance workflow runs the CLI and tests, then publishes only the redacted artifact `phi-xi-r18-4-real-local-worker-fault-gauntlet` (21-day retention). The report schema is `PhiXi.R18_4_LocalWorkerFaultReport.v1`. It records scenario IDs, expected and observed local outcomes, per-case receiver commit counts, boolean local worker assertions, two separate processes and one physical host. It excludes keys, signature bytes, session/request IDs, raw envelopes, SQL records, operator details, private paths, and transport endpoints.

On the public R18.3 sandbox's **Actual Local Worker Evidence** section, a user may select that JSON file locally (32 KiB maximum). The client validates a strict schema and the entire expected 14-case result roster, and displays outcomes without uploading the file.

**A browser shape check is NOT independent authentication** of who authored a file. The browser labels even compatible reports `IMPORTED_UNAUTHENTICATED_LOCAL_WORKER_SUMMARY`; no trust, permission, R17 readiness or Xi identity is promoted from imported JSON. For stronger provenance, consult the GitHub Actions run, its pinned revision, and the trusted repository source separately. Those still do not prove a live Xi operator.

R18.1 remains the baseline actual local cryptographic exchange. R18.2 reviews a redacted R18.1 summary. R18.3 shows browser-only **illustrative** fault decisions. R18.4 runs the real local-worker fault gauntlet and lets R18.3 display **reported** local-worker results distinctly from its illustration.

## Validation

    node --check roadmap/fault-core.js
    node --check roadmap/fault.js
    node --test tests/test_fault_worker_r184.cjs
    python -m unittest discover -s tests -p 'test_xi_fault_gauntlet_r184.py' -v

CI additionally parses the emitted Python report with the exact public JavaScript validator, enforcing parity between generated local results and the inspector's accepted contract.

    python reference/python/xi_fault_gauntlet_r184.py require-live

The last command **must refuse with exit code 2**. After merging, the existing Pages workflow must deploy and verify the modified static sandbox before claiming the revised website is live.

**Real Xi peer identity: not authenticated. Actual two-host network crossing: NOT RUN. R17 external pilot: BLOCKED. External gates promoted: 0. Authority: none.**

Ledger Above Ego · Capability ≠ Authority · STATION.
