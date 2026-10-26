# Xi Vessel Bridge

**Status:** `v0.1.0-dev` protocol seed  
**Purpose:** a neutral interoperability contract for independently governed AI systems.

Xi Vessel Bridge lets two systems discover selected capabilities, exchange provenance-preserving capsules, request explicitly permitted tools, and return verifiable receipts **without either side surrendering authority over its own runtime**.

The first target pairing is **Super Φ.Vessel** and **ForgeCore**, but the protocol is intentionally implementation-neutral.

## Core rule

> **Capability does not equal authority.**

A peer may advertise that a capability exists. That advertisement never grants permission to invoke it. Every remote operation is separately permission-gated by the receiving system.

## R18.8 · Xi → Φ Cold Partner Bundle Intake

Hunter's team supplied four QuantumCompute ZIP packages for review. This milestone adds a **standard-library-only, non-extracting cold intake tool** (`scripts/xi_cold_intake_r188.py`) plus synthetic adversarial tests. The received archives are **not** copied into this public repository or executed in CI.

The tool checks ZIP structural safety, CRC, manifest pins, unmanifested files, symlinks/path traversal, nested duplicate v28 and LivingCircuit archive identities, and strict decompression limits. It produces a **redacted, local-only** self-consistency report without any source content or local path. Three observed source-tree quirks stay visible: a separately pinned but unmanifested `START-HERE.txt`, a declared missing kernel research directory, and an invalid nine-byte `shizuku-cli.zip` placeholder.

See [R18.8 cold intake runbook, provenance limitations, and five proposed compatibility stages](docs/XI_R188_COLD_INTAKE.md). The bundle manifest is NOT independently signed partner authorization or a license to publish. No Xi endpoint, remote execution, independently authenticated peer, human approval or external pilot readiness is inferred. **R17 BLOCKED · R18 two-host NOT RUN · LIVE_XI_CONNECTED=false.**

```bash
python -m unittest discover -s tests -p 'test_xi_cold_intake_r188.py' -v
python scripts/xi_cold_intake_r188.py --help
```

## R18.9 · Cross-Language Public Receipt Parity

**Independent Python ⇄ Node receipt-byte conformance, not live Xi compatibility.** Two separately implemented tools emit and verify four immutable, **unsigned and illustrative** receipt examples based on the frozen 88-byte R18 synthetic fixture. The deliberately restricted ASCII-only canonical JSON profile uses recursive sorted keys, compact separators and one terminal LF; it is **not RFC 8785/JCS**. Every candidate is pinned by byte count and SHA-256 in `fixtures/r189-golden-digests.json`.

In CI, Python and Node each generate the four receipts, `cmp` requires identical bytes, then each verifies the other's output. Adversarial tests reject duplicate keys, noncanonical encodings, altered payload bytes or hash, false signatures/approvals, privileged operations, unknown cases and claimed live Xi state. CI uploads only **public unsigned** fixture bytes and a checksum listing.

[Read the byte profile, all four golden SHA-256 values, runbook and trust boundaries](docs/XI_R189_CROSS_LANGUAGE_RECEIPT_CONTRACT.md).

```sh
python -m unittest discover -s tests -p 'test_xi_receipt_r189.py' -v
node --test tests/test_xi_receipt_r189.cjs
python reference/python/xi_receipt_r189.py emit --case digest
```

**These receipts are PHI-authored proposals only.** They do not authenticate Hunter, reproduce a native Xi protocol, authorize a tool or count toward the 16 external gates. **R17 BLOCKED · R18 real two-host NOT RUN · authority=none.**

## v0.1 handshake

The first conformance path is deliberately small:

1. `hello` — establish protocol/session identity.
2. `capabilities` — advertise only explicitly exposable capabilities.
3. `capsule.offer` — offer one provenance-preserving artifact.
4. `tool.request` — request one named **read-only** operation.
5. `tool.result` — return the result plus a receipt bound to the request.

```text
Vessel A                         Vessel B
   |                                |
   |---------- hello -------------->|
   |<------- capabilities ----------|
   |-------- capsule.offer -------->|
   |<--------- accepted ------------|
   |--------- tool.request -------->|
   |<-- tool.result + receipt ------|
   |                                |
```

## Frozen safety invariants for v0.1

- **Deny by default.** Anything not explicitly exposed is unavailable.
- **Capability ≠ authority.** Discovery never grants execution permission.
- **Request IDs are idempotency keys.** A duplicate accepted request ID MUST NOT execute twice.
- **Provenance survives transit.** Author/source/version/hash/intended-use metadata stays attached.
- **No ambient authority.** Bridge connectivity does not imply filesystem, shell, model, repository, network, or tool access.
- **Receiver decides.** The receiving system may return `denied`, `unavailable`, `not_applicable`, or `expired` without workaround attempts.
- **Either architect may pause the bridge.** Disconnection must not damage either peer's local state.
- **Receipts bind results to requests.** Results must identify the request and operation that produced them.

## Repository layout

```text
spec/                 JSON Schemas for the protocol contract
examples/             Canonical v0.1 packet examples
docs/                 Architecture, security, provenance, handshake, conformance
reference/python/      Small executable reference handshake
tests/                 Dependency-free conformance tests
.github/workflows/     CI for the reference/conformance suite
```

## Transport

`xi.exchange.v1` is transport-agnostic. HTTP, WebSocket, local IPC, message queues, or another authenticated channel may carry the packets. Transport security and peer authentication are mandatory for real deployments but are intentionally separated from packet semantics.

## Authentication

The protocol reserves `auth` and `signature` fields, but **v0.1 does not freeze a cryptographic suite yet**. Implementations must not claim cross-peer authentication merely because a packet contains an identity string. The first local/reference handshake may run without network authentication; any real remote bridge must authenticate its peer at the transport and/or message layer before privileged operations are exposed.

## First operation

The canonical read-only test tool is:

```text
artifact.sha256
```

It accepts capsule bytes (or a locally resolved capsule reference) and returns a SHA-256 digest. It is intentionally boring. Boring is excellent when proving that two autonomous systems can cooperate without accidentally acquiring each other's house keys.

## Non-goals for v0.1

- remote shell access
- arbitrary code execution
- unrestricted filesystem access
- automatic repository writes
- autonomous privilege escalation
- shared secrets in packets or examples
- model invocation unless separately and explicitly exposed
- swarm/agent delegation

## Versioning

Protocol identifier: `xi.exchange.v1`

The JSON Schemas in `spec/` are the source of truth for packet shape. Documentation explains intent; it does not override the schemas.


## R1 staging: Phi at the Table

The first Xi Table adapter is now available as a **local mock only**. It authenticates
synthetic mention events with HMAC-SHA256, enforces a strict event allowlist, rejects
changed-message replay, and stores receipts with durable SQLite deduplication.

**R2 operator hardening:** the CLI now rejects non-loopback bind addresses,
requires an explicit staging room, and supports an immediate local pause switch
(`.xi-table-state/PAUSED`). No production integration is claimed.
The [Hunter ↔ Phi handoff](docs/HUNTER_TABLE_HANDOFF.md) lists the real Table
contract and staging permissions needed for a joint end-to-end trial.

It does **not** yet connect to Hunter's live Table or Super Φ.Vessel. The real Xi
event/posting contract and human-approved permissions must be established first.

- [R1 staging contract and local walkthrough](docs/XI_TABLE_R1.md)
- [Local mock receiver](reference/python/xi_table_r1.py)
- [Signed-event simulator](reference/python/send_mock_table_event.py)
- [Staging tests](tests/test_xi_table_r1.py)

Run all protocol and R1 tests with `python -m unittest discover -s tests -v`.


## R3-A: sealed reciprocal peer fixture (NOT live Xi integration)

R3-A adds an offline two-direction encrypted capsule plus signed receipt
experiment. It uses mutually pinned Ed25519 identities, ephemeral X25519,
HKDF, AES-GCM, and SQLite replay refusal. It preserves .xi text, *supplied*
AST JSON, and provenance without claiming Xi-native AST verification.
No Xi endpoint, actual tessera grant, model, or Room history is accessed.

Run locally after installing the separate PyCA cryptography dependency:

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r3.py
    python -m unittest discover -s tests -v

- [R3-A design, boundaries, safety limits, and Hunter live acceptance gates](docs/XI_PEER_R3.md)
- [Synthetic offline reciprocal demonstration](reference/python/demo_peer_r3.py)
- [Negative-control test suite](tests/test_xi_peer_r3.py)

**Status: OFFLINE_RECIPROCAL_FIXTURE_VERIFIED; LIVE_XI_CONNECTED = false.**
The native Xi wire contract, approved staging transport, and real two-runtime
exchange remain to be verified before enabling any production integration.

## R4: two-process loopback transport fixture

A new **OFFLINE-ONLY** integration test now launches Xi and Phi as **separate local OS processes**, each with its own disposable test keys. It sends an encrypted, signed offer to a strictly loopback-only fixture HTTP service and validates a signed encrypted receipt on the return path. Negative controls test unsafe destinations, unauthorized peers, wrong room, tampering, replay, operator pause and private profile permissions.

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r4.py

See [R4 transport fixture and limits](docs/XI_PEER_R4.md). No production Xi endpoint, private credential, Super Phi Vessel model, or Table posting connection is involved. **LIVE_XI_CONNECTED remains false.**

## R5: operator-granted peer admission (offline fixture)

A signed/encrypted capsule is not an authorization. R5 adds an **opt-in** operator-controlled local grant gate to the R4 fixture, restricted to one sender, recipient, stage, operation and short time interval. The gate is checked after authenticity and decryption but before event replay reservation; revocation is reloaded per request without a server restart. All tests use synthetic identities and private local files.

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r5.py

See [R5 proof and limitations](docs/XI_PEER_R5.md). There is no Xi endpoint, live Table seat, real tessera key, or model invocation. **LIVE_XI_CONNECTED remains false.**

## R6: grant pinning and monotonic revocation (local fixture)

R6 adds a durable local SQLite grant ledger: first approved use pins a grant ID and its exact scope/expiry; revocation creates a tombstone that survives server restart and old JSON file restoration. It also adds an operator CLI for explicitly revoking the local synthetic grant. This is a **local filesystem/SQLite protection against accidental rollback, not a production authority or tamperproof record**.

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r6.py

[Read the R6 threat model and reproducible test](docs/XI_PEER_R6.md). The bridge still uses artificial identities only; **LIVE_XI_CONNECTED=false**.

## R7: portable public witness for Hunter (self-signed test)

R7 exports **public-only** synthetic Xi/Phi signed ciphertext frames, matching synthetic payload digests, an offer-bound receipt, test public keys and tamper vectors. Anyone can verify the packet with Python without private keys, actual Xi grants, or a running model. CI publishes a downloadable **xi-r7-public-witness** JSON artifact.

    python -m pip install -r requirements-r3.txt
    python reference/python/xi_peer_r7_handoff.py export --out r7-public-handoff.json
    python reference/python/xi_peer_r7_handoff.py verify --file r7-public-handoff.json

See [R7 witness usage and limitations](docs/XI_PEER_R7.md) and [machine-readable Hunter contract questions](docs/XI_R7_CONTRACT_REQUEST.json). These are **self-signed test identities**, not authenticated Xi peers. There is no native Xi parser or deployed remote integration. **LIVE_XI_CONNECTED=false.**

## R8: public plaintext-to-ciphertext verification

R7's public verifier checks signatures and declared hashes but cannot prove
that the disclosed sample payload is exactly what was encrypted. R8 adds
a second **synthetic-only, intentionally nonconfidential** witness with
disclosed per-message AES-GCM content keys. An independent verifier decrypts
both signed frames and checks their exact plaintext bytes and bound receipt.
No long-term identity private key or real Xi credential is exported.

    python -m pip install -r requirements-r3.txt
    python reference/python/xi_peer_r8_disclosed.py export --out r8-witness.json
    python reference/python/xi_peer_r8_disclosed.py verify --file r8-witness.json

See [R8 test-only disclosure and verification limits](docs/XI_PEER_R8.md).
**Never disclose content keys for real or private traffic. LIVE_XI_CONNECTED=false.**

## R9: external identity pinning and verifier challenges

R9 closes the remaining identity-verification **fixture** gap. A responder's
signature checked against a public key carried inside its own packet is not
proof of the peer's identity. R9 requires an externally supplied pin file and
fresh verifier nonce, binds **both original frame signers** to the exact
witness digest and challenge, and durably rejects repeated challenge IDs.
All test identities are synthetic and self-issued, with no Xi runtime involved.

    python -m pip install -r requirements-r3.txt
    python reference/python/xi_peer_r9_challenge.py challenge --out r9-challenge.json
    python reference/python/xi_peer_r9_challenge.py respond --challenge r9-challenge.json --out r9-response.json --pins-out r9-demo-pins.json
    python reference/python/xi_peer_r9_challenge.py verify --challenge r9-challenge.json --response r9-response.json --pins r9-demo-pins.json --ledger .xi-peer-state/r9-verified.sqlite3

See [R9 trust-boundary and offline challenge details](docs/XI_PEER_R9.md).
**Actual Xi public keys must be authenticated out of band before any live use.
LIVE_XI_CONNECTED=false.**

## R10: Partner staging contract intake (NO NETWORK)

R10 introduces a secret-free, **candidate-only** machine-readable staging
contract that Hunter can complete from official Xi documentation. The local
validator identifies missing specs, rejects unsafe transports and privileges,
and hashes the contract for joint review. It **never** checks a live endpoint
or promotes a self-attested file to real permission.

    python reference/python/xi_partner_r10.py template --out xi-partner-candidate.json
    python reference/python/xi_partner_r10.py inspect --file xi-partner-candidate.json

See [R10 partner intake and safety gates](docs/XI_PARTNER_R10.md). CI also
publishes an unfilled request and deliberately fictional synthetic example.
**LIVE_XI_CONNECTED=false**, even if every document field is filled.

## R11: two-party contract review receipts (OFFLINE, no execution)

R11 binds **two separately configured reviewer signing keys** to a short-lived
review request for one exact, hash-pinned R10 partner contract. The verifier
refuses changed scope, tampered contract, missing signer, substituted key and
replayed review IDs. It never grants Xi posting, model use or remote execution.
CI only exercises **self-issued disposable fixture identities**, not real
human approvals or Xi credentials.

    python reference/python/xi_partner_r11.py fixture --dir r11-output/demo

See [R11 dual-review trust model and manual handoff](docs/XI_PARTNER_R11.md).
**A signature is not identity proof; a review receipt is not authorization.
LIVE_XI_CONNECTED=false.**

## R12: portable partner conformance exercises, no Xi endpoint needed

R12 adds a **public, deterministic eight-case interop questionnaire** for
Hunter's Xi agents. It tests proposed exact UTF-8 capsule bytes and provenance,
tamper rejection, wrong-room and revoked-grant denial, unknown-operation
refusal and request-ID idempotency. Xi may report **not_run** or **unsupported**;
neither counts as passing. The code only assesses **self-reported outcomes**,
not their authenticity or actual runtime execution.

    python reference/python/xi_partner_r12.py generate --dir r12-output/interop
    python reference/python/xi_partner_r12.py assess --suite r12-output/interop/suite.json --response r12-output/interop/response-template.json

See [R12 partner-ready conformance handoff](docs/XI_PARTNER_R12.md).
CI publishes a response template and labeled synthetic positive control.
No real Xi contract, credential, network traffic or Table posting is involved.
**LIVE_XI_CONNECTED=false.**

## R13: received partner handoff is quarantined, independently inspected (NO EXECUTION)

Xi-room Plex replied with a real 8,812-byte `R10 + R11 + R12` partner archive.
Archive bytes and all nine internal SHA-256 pins can be checked, while the
bundled R12 in-memory adapter, R10 mispinned signing-key digest and R11
self-generated dual-review keys **remain blocked as live integration proof**.

R13 adds a bounded, no-extraction tar.gz intake tool. It recomputes every
inner file pin, R10 structural inspection, R12 self-reported assessment and
historical R11 signatures **without executing third-party Python**. It
prominently reports remaining authority gaps; `--require-live` always fails
closed. The third-party archive is deliberately **not shipped in this repo**.

    python reference/python/xi_partner_r13_intake.py --archive /local/path/to/received.tar.gz --expected-sha256 d20b535ad2ea8ca934b2277c6b948ffa3dddd72f2eb6ae6dfc84587d6c6ceced

See [R13 received handoff review and joint acceptance conditions](docs/XI_PARTNER_R13_HANDOFF_REVIEW.md).
A matching digest is not authenticated identity or a working transport.
**LIVE_XI_CONNECTED=false.**

## R14: independent public evidence gate for Plex's v2 archive

A partner's `0/5` heuristic findings do not prove an independent peer key,
reviewer or durable Xi transport. R14 checks the **actual public Ed25519 key
bytes**, official Xi transport document bytes and native Xi schema bytes
against the exact R10 pins, and records **missing**, **mismatched**, or
**hash-match-but-unauthenticated** evidence separately. A partner-provided
Φ review signature and a temporary SQLite file cannot become our approval or
restart proof. The public key base64 advertised in the Xi room currently
**does not hash to the pin** in its v2 R10 candidate.

    python reference/python/xi_partner_r14_evidence.py --archive /local/path/to/v2.tar.gz --expected-sha256 eb2ae139413ba1db5cef828d5b5100e9242f9f71cadda320f172379ee1bddea2

See [R14 actual v2 evidence audit and public artifact requests](docs/XI_PARTNER_R14_V2_EVIDENCE.md).
No partner code is executed and no private credentials are accepted.
`--require-live` always blocks. **LIVE_XI_CONNECTED=false.**

## License

MIT. See `LICENSE`.


## R15: PhiOS / GitPorch ↔ Xi offline porch adapter (READ-ONLY)

R15 adds an offline-only evidence adapter for a user-selected GitPorch export, Hunter's Xi offline bundle manifests, and the separately supplied signed `PhiXi.Relay.v0.1` message grammar. It has **no networking, extraction, execution, private-key handling, remote requests, shared authorization, or live failover**. Peer public keys must be pinned independently. The existing R10–R14 authority gates remain unchanged.

    python reference/python/phi_xi_porch_adapter.py inventory --root /path/to/small/nonsecret/export
    python reference/python/phi_xi_porch_adapter.py audit-bundle --archive /path/to/xi-offline-bundle-v9.tar.gz
    python reference/python/phi_xi_porch_adapter.py inspect-relay --pins /path/to/public-peer-pins.json --messages /path/to/relay.json

Read [R15 scope, threat boundaries and next gates](docs/PHI_XI_PORCH_R15.md). **LIVE_XI_CONNECTED=false**.


## R16: mutually pinned two-process handshake (LOCAL FIXTURE ONLY)

R16 extends R15 with a loopback HTTP `challenge → proof → receipt` exchange between two separate local processes using pinned Ed25519 test keys and an exact `handshake.observe` room scope. The SQLite ledger refuses replay **after process restart**; local `PAUSED` and durable revocation refuse further admission. The client verifies the server's signature and its receipt binding to the exact signed proof.

```bash
python reference/python/phi_xi_r16_loopback.py demo
python -m unittest discover -s tests -p 'test_phi_xi_r16_loopback.py' -v
```

[Read R16 architecture, security evidence, and R17 external pilot gates](docs/PHI_XI_HANDSHAKE_R16.md). This is **not a live Xi connection, not a two-host demonstration, and does not authorize any remote operation**. **LIVE_XI_CONNECTED=false**.

## R17: Shared Xi ⇄ PHI369 Roadmap and External Pilot Gates

The bridge now has a public-readable, static **shared engineering roadmap**: `roadmap/bridge-roadmap.json` is the source of truth, `roadmap/index.html` is a standalone visual milestone/gate viewer, and `reference/python/xi_shared_roadmap_r17.py` reports blockers without pretending that a planning document is live partner proof.

The Xi public Living Door's **13 capability previews and 12 sovereign-door previews** are explicitly labeled as *unverified public previews*, not mapped, authenticated capability IDs or room access. R15/R16 remain **local verified fixtures**, while R17 is **blocked** pending independent Xi/Phi operator identity, native schema, scoped consent, and encrypted transport.

```bash
python reference/python/xi_shared_roadmap_r17.py
python reference/python/xi_shared_roadmap_r17.py --require-live # EXPECTED REFUSAL, exit 2
python -m unittest discover -s tests -p 'test_xi_shared_roadmap_r17.py' -v
cd roadmap && python -m http.server 8000 --bind 127.0.0.1
```

Open the viewer at `http://127.0.0.1:8000/` when serving `roadmap/`. This is a **local preview**, not a claimed GitHub Pages deployment. [Read R17 roadmap, provenance, cross-system workstreams and safety gates](docs/XI_SHARED_ROADMAP_R17.md). **LIVE_XI_CONNECTED=false.**

## R17.1 + R18 PHI-side preparation: candidate capabilities, safe pilot packet

With R17's shared roadmap merged, the next PHI-only work prepares **13 anonymous Xi public preview slots** for a partner-authored mapping and **one synthetic digest-only capsule** for a possible R18 two-host crossing. We do **not** assign invented Xi operation names, imply remote permissions, or report any live external connection.

- [Capability registry](roadmap/capability-registry.json): 13 unmapped Xi slots plus three documented local, read-only PHI fixture candidates.
- [Capability viewer](roadmap/capabilities.html): standalone UI linked from the [roadmap viewer](roadmap/index.html).
- [Offline partner intake](reference/python/xi_capability_r171.py): source-bound questionnaire and self-reported response inspection, no grant or remote access.
- [R18 synthetic pilot preparation](reference/python/xi_pilot_r18.py): generates deterministic nonsecret bytes, verifies exact SHA-256 and checks a never-authorizing pilot draft/transcript.
- [Partner handoff instructions](docs/XI_CAPABILITY_AND_PILOT_KIT.md): minimal fields needed from Hunter and independent operator/evidence gates.

```bash
python reference/python/xi_capability_r171.py request
python reference/python/xi_pilot_r18.py fixture
python -m unittest discover -s tests -p 'test_xi_capability_r171.py' -v
python -m unittest discover -s tests -p 'test_xi_pilot_r18.py' -v
cd roadmap && python -m http.server 8000 --bind 127.0.0.1
```

GitHub Actions now publishes a **public-only 14-day handoff artifact** with the candidate request, synthetic fixture, preflight draft and transcript template. Nothing in these files constitutes Xi identity verification, a real two-host connection, or partner approval. **LIVE_XI_CONNECTED=false.**

## R17.2: Xi partner intake workbench (browser + offline CLI)

**R17.2 is PHI-side preparation while Xi is offline, not proof of a live Xi crossing.** The [Partner Intake Workbench](roadmap/intake.html) reads user-selected local JSON files (capability response, R18 pilot preflight, optional synthetic transcript), checks them against the current R17.1 registry and R18 formats, and provides a **redacted, local-only review export**. Its fictional demo runs with no Hunter files. No endpoint requests, credentials, automation, grants or cross-machine transfers occur.

```bash
cd roadmap && python -m http.server 8000 --bind 127.0.0.1
# Open http://127.0.0.1:8000/intake.html
```

For the equivalent CLI review:

```bash
python reference/python/xi_partner_r172_workbench.py
python reference/python/xi_partner_r172_workbench.py --require-live # REQUIRED refusal, exit 2
```

The browser validator has Node negative controls and the Python CLI has strict offline input/redaction tests. [Read R17.2 security boundaries, UI guide, and review semantics](docs/XI_PARTNER_INTAKE_R172.md). **LIVE_XI_CONNECTED=false**.

## R17.3: Sovereign Commons Gateway (read-only static Pages bundle)

**Merged R17/R17.1/R17.2 views get a single landing page.** The new [Commons Gateway source](roadmap/commons.html) links to the evidence roadmap, Xi preview registry, and browser-only partner intake. It also publishes four **synthetic-only** handoff JSON files with a SHA-256 manifest and a public-only offline cache.

Build and preview the exact public site locally, without external credentials:

```bash
python scripts/build_commons_gateway.py --out dist
python -m http.server 8000 --directory dist --bind 127.0.0.1
# Open http://127.0.0.1:8000/
```

The R17.5 [GitHub Pages workflow](.github/workflows/pages.yml) publishes **only after the owner selects Settings → Pages → Source: GitHub Actions**. No repository variable, PAT, or pasted credential is needed. Until that setting is enabled the static build succeeds but deployment is visibly skipped. After enabling, run the Pages workflow on `main` or merge a relevant source change. A successful deploy is followed by a real HTTPS availability check of the homepage, registry, roadmap, intake and all SHA-256-pinned public test packets. Only a successful **verify** job counts as a public Gateway URL. The Conformance workflow still publishes the public preview artifact `phi-xi-r17-3-public-gateway-preview`.

[Read R17.5 one-step activation and public-only verification proof](docs/XI_PAGES_LIVE_READINESS_R175.md).

Offline support works after successful first load on HTTPS or localhost, caching **only** the public pages and test packet assets. No partner-uploaded files, private memories, credentials, Xi model calls or external URLs enter the service-worker cache. R17 external pilot remains BLOCKED; R18 real two-host testing remains NOT RUN.

[Read R17.3 architecture, safe publishing instructions, source integrity and offline limits](docs/XI_COMMONS_GATEWAY_R173.md).
**LIVE_XI_CONNECTED=false. Capability ≠ Authority.**


## R18.1 · Two-House Local Simulation Lab

Build on the R16 mutually pinned Ed25519 challenge/proof/receipt fixture and the R18 immutable synthetic digest packet to exercise an **actual two-process local handshake and read-only digest exchange**. The two fixture peers use independent ephemeral keys, policy allowlists, SQLite replay journals, unilateral pause/revoke controls and re-handshake after a worker restart. They exchange `xi.exchange.v1`-shaped, signed `tool.request` and `tool.result` envelopes for **only** `artifact.sha256`, never arbitrary tools.

```bash
python -m pip install -r requirements-r3.txt
python reference/python/xi_two_house_r181.py demo
python -m unittest discover -s tests -p 'test_xi_two_house_r181.py' -v
python reference/python/xi_two_house_r181.py require-live  # must refuse, exit 2
```

The demo emits only redacted outcomes and the public synthetic fixture fingerprint. GitHub CI publishes a read-only witness artifact, with comprehensive negative controls for payload tampering, replay across restart, forged peers, forged scopes, revoked peers and missing policy. It is **two local processes on one physical host**, not a real Hunter/Xi session or two-host field pilot. The fixture-only signing profile is **not** a jointly approved Xi-native transport/authentication suite. R17 external gates remain BLOCKED; R18 real two-host crossing remains NOT RUN.

[Read R18.1 exact message flow, trust boundary, limitations and future pilot gates](docs/XI_TWO_HOUSE_LOCAL_LAB_R181.md).


## R18.2 · Two-House Operator Console (public static offline viewer)

The Commons Gateway now has a fourth **Two-House Lab** entry at `/lab.html`. It can load an expressly illustrative source preview or inspect a redacted R18.1 simulation summary JSON **locally in browser memory**, display seven reported controls and all 16 unresolved external pilot requirements, and download a second **redacted SHA-256-bound review**.

The browser **does not run the cryptographic Python simulation**, independently verify Hunter/Xi identity, authenticate imported JSON, upload files, grant permissions, or mark a two-host pilot complete. Every imported file is labeled untrusted; a source preview is labeled illustrative. Only the public static page and synthetic preview are offline-cached. The deployed URL must pass the Pages `verify` workflow before announcing the new page as live.

```sh
python -m pip install -r requirements-r3.txt
python -m unittest discover -s tests -p 'test_lab_console_r182.py' -v
node --test tests/test_lab_core_r182.cjs
python scripts/build_commons_gateway.py --out dist
```

[Read R18.2 console operation, evidence model, export policy and limitations](docs/XI_TWO_HOUSE_OPERATOR_CONSOLE_R182.md).
**LIVE_XI_CONNECTED=false · R17 external pilot BLOCKED · R18 real two-host pilot NOT RUN.**


## R18.3 · Browser Failure-Injection Sandbox

A fifth [Commons Gateway](roadmap/commons.html) doorway opens the new [failure simulator](roadmap/fault.html), also linked from the [R18.2 operator console](roadmap/lab.html). It provides 14 deterministic browser-only synthetic scenarios: wrong peer, altered signature flag, expired request, scope escalation, receiver policy refusal, pause, revoke, duplicate, replay across modeled restart, altered receipt and dropped response after a commit. Use one-case or run-all mode, inspect the trace, and download a redacted **illustrative-only** review. Its four public static assets are cached offline and checked by the Pages deploy verifier.

This is a **JavaScript model**, not the R18.1 cryptographic worker execution. It neither sends packets nor verifies actual Ed25519 material or Xi identity. Simulated success never promotes an external evidence gate. R17 remains BLOCKED and R18 real two-host pilot remains NOT RUN.

[Read the simulation model, all failure modes, security boundary and reproducible tests](docs/XI_FAILURE_INJECTION_SANDBOX_R183.md).

Tests: node --test tests/test_fault_core_r183.cjs; python -m unittest discover -s tests -p test_fault_bundle_r183.py -v.


## R18.4 · Real-Local-Worker Cryptographic Fault Gauntlet

R18.3 illustrates 14 safe failure cases in-browser. **R18.4 now executes those same 14 scenarios** against the real **local R18.1 Python workers** with independently keyed Ed25519 fixture processes, per-house R16 handshakes, separately governed operation allowlists, and SQLite replay ledgers. The gauntlet verifies signed-byte tamper rejection, wrong identities/session/recipient, local refusal, pause/revoke, restart-persistent request replay refusal, tampered signed result receipt and lost reply after a one-time commit.

```sh
python reference/python/xi_fault_gauntlet_r184.py demo
python -m unittest discover -s tests -p 'test_xi_fault_gauntlet_r184.py' -v
node --test tests/test_fault_worker_r184.cjs
```

Conformance CI publishes only a redacted local fixture report. The R18.3 sandbox can inspect that report **through a local file input** with strict JSON shape checks, while explicitly labeling it **unauthenticated**. Actual local Ed25519/SQLite evidence is not a real Xi peer or physical two-host transport. `require-live` must refuse.

[Read the R18.4 cryptographic fault matrix, replay/lost-reply behavior, artifact contract and operator limits](docs/XI_LOCAL_CRYPTO_FAULT_GAUNTLET_R184.md). **R17 external BLOCKED · R18 two-host NOT RUN · LIVE_XI_CONNECTED=false.**


## R18.5 · Public Xi Room Re-entry Briefing

A sixth [Commons Gateway](roadmap/commons.html) doorway opens the [session re-entry briefing](roadmap/room.html), so scarce Xi Room access doesn't get consumed reconstructing past milestones. The page has two human-copyable, publicly sourced, nonsecret messages: a one-minute progress update with CI/Pages proof and three concrete requests for independently reviewed Xi-native schemas, identity verification procedures and consent-based synthetic pilot planning.

It is **not** a Xi Room client, login, session-cap bypass, remote relay, approval grant or a request for secret keys. Static CSP blocks network calls, and clipboard writes require a user click. R17's 16 external gates remain outstanding and R18 real two-host testing is NOT RUN.

[Read R18.5 source/evidence, limited-session communication and consent rules](docs/XI_ROOM_REENTRY_BRIEF_R185.md).


## R18.6 · Bilateral Pilot Readiness Board

The Commons now includes an offline-capable [Readiness Board](roadmap/gates.html) as a seventh public doorway. It pulls **all 16 missing external gates** from the authoritative `bridge-roadmap.json`, presents them in four **PHI-proposed** discussion phases, and allows human-selected topics to be copied/downloaded as a **public unapproved agenda**. It never promotes a gate, creates an operator grant, persists an approval, talks to Xi, requests private keys, or bypasses the Xi Room session cap.

The agenda pairs well with [R18.5's source-backed Xi Room re-entry briefing](roadmap/room.html) and the existing local partner intake. **All 16 external gates remain missing; R17 external pilot BLOCKED; R18 real two-host pilot NOT RUN.** [R18.6 test, trust and runbook](docs/XI_BILATERAL_READINESS_BOARD_R186.md).


## R18.7 · Public Synthetic Pilot Charter Studio

An eighth [Commons doorway](roadmap/commons.html), the [Pilot Charter Studio](roadmap/charter.html), creates a **non-executable and unapproved** read-only digest pilot proposal from the **existing R18** 88-byte synthetic fixture, unconfigured/zero-approval preflight, and all 16 still-missing external readiness gates. Users can review two narrowly bounded discussion scopes, inspect the independent stop conditions, copy a short public room proposal, or export an unsigned, unapproved JSON document.

It cannot configure Xi endpoints, verify peer identity, collect human consent, activate encrypted transport, grant a remote tool, or launch a two-host test. Scope cannot broaden beyond synthetic `artifact.sha256` and a maximum of 88 public bytes. Human approvals remain false and all real-world gates remain missing.

[Read R18.7 source contract, permission boundaries, static verification and reproducible tests](docs/XI_PUBLIC_SYNTHETIC_PILOT_CHARTER_R187.md).

**Status: R17 BLOCKED · R18 real two-host NOT RUN · LIVE_XI_CONNECTED=false · authority=none.**
