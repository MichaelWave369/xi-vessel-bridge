# R4: Two independently running local peers

**Status: R4_TWO_PROCESS_FIXTURE_VERIFIED (CI/local-only). LIVE_XI_CONNECTED = false.**

R3-A proved sealed messaging and bound receipts in memory. R4 turns this into an independently running **Xi-fixture server subprocess** and **Phi-fixture client subprocess**, using a hard-coded 127.0.0.1 JSON endpoint. It is transport engineering for our own test wire, **not** a claim that Hunter's actual Xi Room or ForgeCore uses this endpoint.

## First reproducible run

Use Python 3.12+:

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r4.py
    python -m unittest discover -s tests -v

The driver creates a temporary private directory and two unique, disposable in-memory-generated local identities. It writes two owner-only **test** profiles (mode 0600 on POSIX) and runs the receiver and sender as **separate OS processes**. Once the round trip finishes, it shuts down the server and deletes both private profiles. They are never printed, uploaded or committed.

The only expected success record is:

    {
      "status": "R4_TWO_PROCESS_FIXTURE_VERIFIED",
      "receipt_matches_offer": true,
      "live_xi_connected": false
    }

The status is asserted by the client **only after verifying a signed, AES-GCM-protected reply** bound to its original request ID and content digest. A server 200 without that verified receipt is not success.

## Explicit threat boundaries

- The HTTP server **binds only 127.0.0.1** using the Python standard library HTTPServer. The client refuses every URL except http://127.0.0.1:<port>/v1/fixture/capsule, disables proxies and refuses redirects. No real Xi URL is called.
- Only two endpoint paths exist: GET /healthz and POST /v1/fixture/capsule; the latter accepts only a sealed capsule.offer and returns a sealed capsule.receipt. No model calls, Table posting, shell, arbitrary tools, repo writes, private room history, or service credentials.
- Each peer must have the other's **public** identity keys pinned in the locally created profile. The incoming packet does not enroll peers. The local secret profile is opened with no-follow on supporting POSIX systems and refuses group/world permissions; **not a production secret vault or an audited Windows ACL boundary**.
- The R3 Ed25519 signature covers envelope metadata and ciphertext; X25519/HKDF/AES-256-GCM encrypts the payload. The receiver verifies before returning a separately signed encrypted digest-bound receipt. The Xi-native .xi parser is **not** invoked; supplied AST JSON is preserved, not semantically certified.
- Each event ID is atomically reserved in the receiver's SQLite ledger. Identical replays and changed requests using the same event ID both fail closed. No automatic retry, deduplicated remote posting, or production crash recovery is claimed.
- Creating a PAUSED file in the receiver's configured local state directory returns 503 for subsequent fixture POSTs, including replay attempts. The local health response explicitly says live_xi_connected:false.
- Request/response caps, strict field sets, timestamp checks, wrong-peer rejection and HTTP ingress tests cover common malformed/misrouted scenarios. **No production DoS, secure deployment, TLS, revocation, key recovery, credential rotation, multi-tenant isolation, or independent security audit** is provided.
- The demo's fixture private keys are intentionally short-lived local test material. R4 requires exact test-only profile shape. **Never paste the reported uploads/mikey-tessera-25661.key grant here, into shell history, CI, or GitHub.**

## What Hunter and Phi need before a real crossing

1. Both parties review [R3-B acceptance gates](XI_PEER_R3.md) and the [Hunter Table handoff](HUNTER_TABLE_HANDOFF.md).
2. Hunter specifies actual **documented** Xi staging delivery or poll API, per-peer scope, error codes and wire format. The path in this fixture is **not** proposed as Xi's production API.
3. Peer public fingerprints are explicitly approved out of band; secrets stay solely in appropriately secured operator secret storage.
4. Each runtime exchanges one harmless capsule through its actual staging channel, independently verifies the other's origin and payload, records bound receipts and tests revocation, tamper, replay, wrong room and timeout.
5. Only then change the specifically verified capability from OFFLINE_ONLY to LIVE_STAGING_VERIFIED. Never label untested Table posting or distributed computation live.

This is a **transport proof** using two processes, not a real Xi network integration.

**Ledger above ego. Capability does not equal authority.**
