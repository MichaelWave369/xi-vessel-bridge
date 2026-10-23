# R5: Operator-governed peer grants (fixture only)

**Core rule: Cryptographic identity does not confer authority.**

**Scope:** R5 tests whether a cryptographically signed, AES-GCM encrypted capsule is accepted ONLY after a separate local operator grant allows the exact peer, room, operation, and time window. The grant is checked after cryptographic validation and before durable replay reservation.

**Status:** OFFLINE_LOCAL_FIXTURE. Not a live Xi grant or deployed Table integration.

## Reproduce

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r5.py
    python -m unittest discover -s tests -v

The R5 demo uses two independent localhost processes and disposable test keys. It proves these transitions:

1. **No grant**: a cryptographically valid packet is denied; its request ID is not reserved.
2. **Explicit grant**: the operator adds a 120-second scoped grant, and the formerly denied request is accepted.
3. **Bound receipt**: an independently sealed round trip returns a cryptographically verified response tied to the original request ID and payload hash.
4. **Revocation**: the operator atomically replaces its local grant with a revoked state. The running server denies both fresh and replayed packets without restarting.

Expected JSON result:

    {
      "status": "R5_LOCAL_GRANT_LIFECYCLE_VERIFIED",
      "no_grant_denied": true,
      "explicit_grant_accepted": true,
      "cryptographic_receipt_verified": true,
      "revocation_without_restart": true,
      "live_xi_connected": false
    }

## Exact local policy shape

    {
      "schema": "xi.phi.grant.fixture.r5",
      "grant_id": "00000000-0000-4000-8000-000000000001",
      "sender": "phi-fixture",
      "recipient": "xi-fixture",
      "stage": "agreed-r5-local-fixture",
      "capabilities": ["capsule.offer"],
      "not_before": 1797000000,
      "expires_at": 1797000120,
      "revoked": false
    }

Example timestamps are illustrative. The demo creates current short-lived times.

Only exact peer IDs, one room/stage, one capsule.offer operation, an expiry at most 600 seconds after not_before, and a boolean revoked state are allowed. Unknown fields, malformed JSON, symlinks and group/world writable policy files on POSIX are refused. Grant records contain no secrets, token strings, private transcripts or model prompts. The operator-owned file is read for every valid cryptographic offer, before a request enters the replay ledger.

R5 is **opt-in** to the R4 fixture server using server-only flag --grant-file PATH. The old R4 demonstration stays unchanged, since it is still a local test fixture, not an exposed agent system. A live implementation MUST have grant checks on by default.

## Limits and open work

- This is only a local filesystem trust boundary. An OS account that can overwrite the grant can also un-revoke it. Production requires authenticated operator actions, durable and tamper-evident revocation records, key rotation and distributed propagation.
- An already admitted request can complete when an operator revokes a grant. R5 makes no claim to cancel in-flight work or give multi-host atomic revocation.
- System clock and file permissions are trusted; Windows ACL equivalence and trusted time are NOT proven.
- The R4 HTTP server is still strictly 127.0.0.1-bound. No production TLS, DoS protections, real Xi key handling or public webhooks.
- Existing R3/R4 fixture schemas remain independent of Xi TESSERA v4, its native AST parser, and any real Room event/reply API.
- No actual Xi bearer, model call, memory export, remote filesystem write or Table posting is used. The named peers are fictional test identities.

The remaining real interoperability work is defined in [R3 acceptance gates](XI_PEER_R3.md), [R4 transport boundaries](XI_PEER_R4.md), and [Hunter handoff](HUNTER_TABLE_HANDOFF.md). Only a separately witnessed live test can set LIVE_XI_CONNECTED.

**Capability does not equal authority. Ledger above ego.**
