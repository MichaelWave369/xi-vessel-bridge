# R16: mutually pinned PhiOS ↔ Xi local handshake fixture

**Status:** `TWO_PROCESS_LOOPBACK_FIXTURE`, **not live Xi**, **not a real two-machine crossing**, and **not a deployed service**. `LIVE_XI_CONNECTED=false`.

R16 builds on the R15 read-only porch evidence adapter and R3–R14 trust-boundary work. Two independent local Python processes perform a narrow signed challenge → proof → receipt round trip over `127.0.0.1` HTTP. Both identities are pinned by the local fixture before exchange. Each message carries an explicit room and **only** `handshake.observe` scope.

This is NOT a bridge from `PhiXi.Relay.v0.1` to `xi.exchange.v1`; the separate `PhiXi.Handshake.R16.fixture.v1` grammar is intentionally isolated and must not be mislabeled as native Xi packets.

## What is actually demonstrated

1. A server signs a short-lived challenge addressed to exactly one pinned client public key.
2. The client verifies the server against an independently provided public-key pin and signs a response binding the room, server, challenge ID, nonce, and fresh client nonce.
3. The server checks the pinned client signature, allowed room, `handshake.observe` scope, fresh challenge, no local pause, and durable revocation.
4. The server consumes the challenge exactly once in a SQLite transaction before generating a signed receipt.
5. The client verifies the signed receipt, including a SHA-256 of the *exact signed proof bytes*, sender/receiver IDs, original challenge ID and client nonce.
6. Duplicate proof is rejected, **including after server process restart**. A local `PAUSED` file and durable local revocation also deny admission.

Only synthetic, short-lived **fixture** keys are created by the demonstration, in a temporary directory that is deleted afterward. No real Hunter or Mikey credentials are read, no external network address is used, and no asset, repository, model, or tool operation is executed.

## Run (no GitHub checkout required in the cloud)

From the `xi-vessel-bridge` checkout:

```bash
python -m pip install -r requirements-r3.txt
python reference/python/phi_xi_r16_loopback.py demo
python -m unittest discover -s tests -p 'test_phi_xi_r16_loopback.py' -v
python -m unittest discover -s tests -v
```

The fixture's successful JSON includes `R16_LOCAL_FIXTURE_PASS` and `live_xi_connected: false`. Fail-closed checks include an unpinned key, signed content tampering, wrong room, stale proof, signed receipt mutation, replay after restart, pause and durable revocation.

## Operator CLI (localhost-only, test peers)

The entrypoint also provides `serve`, `client` and `revoke` for explicit local fixture configuration:

```text
serve --host 127.0.0.1 --port PORT --state LOCAL_STATE --key LOCAL_SERVER_ED25519_RAW32_FILE --peer PINNED_CLIENT_ED25519_PUBLIC_ID --room STAGING_ROOM
client --port PORT --key LOCAL_CLIENT_ED25519_RAW32_FILE --server-pin PINNED_SERVER_ED25519_PUBLIC_ID --room STAGING_ROOM
revoke --state LOCAL_STATE --key LOCAL_SERVER_ED25519_RAW32_FILE --peer PINNED_CLIENT_ED25519_PUBLIC_ID --room STAGING_ROOM
```

This CLI intentionally has no commands to create a grant, bind to a LAN or public address, or transmit any artifact. Private key files must contain 32 raw bytes and must be owner-only on POSIX. Never commit them to Git or send them in chat. If the local state directory contains `PAUSED`, incoming messages are denied; `revoke` writes a persistent tombstone into the local SQLite ledger.

## Evidence and limits

| Check | Status | Important caveat |
|---|---|---|
| Ed25519 mutual key possession | Tested with synthetic independent keys | Key-to-human / key-to-Xi binding still unverified |
| Exact signed proof and receipt binding | Tested | No Xi-native parser or production operation |
| Durable server-side challenge replay refusal | Tested across separate server process restarts | Ledger assumes an intact local filesystem and clock |
| Local pause and persisted revocation | Tested | No external synchronized governance |
| Network hop | Real HTTP between **two local processes** on 127.0.0.1 | Not a two-host/LAN/WAN transport, no TLS profile |
| Bundle transfer / mutual mirror | Not supported | R15 manifest inspector remains read-only |

These proofs cannot be used as live deployment receipts or substituted for the R10–R14 independent authority gates. GitHub CI green proves the **fixture** behaves as specified, not that a remote Xi seat has participated.

## Next: R17 external pilot gates

Do **not** open the listener on the LAN just by changing an address. A genuine two-machine field pilot requires independent out-of-band public-key identity verification with both operators; a mutually agreed native route/schema and `xi.exchange.v1` mapping; authenticated, encrypted transport such as mTLS; scoped human approval and independent policy files on both machines; durable admission/audit receipts; controlled error/restart/revocation experiments; and user-approved private-data transfer boundaries.

The first external test should carry only a small, consensual, synthetic digest and should never grant repo writes, model invocation, shell access, or silent file synchronization.
