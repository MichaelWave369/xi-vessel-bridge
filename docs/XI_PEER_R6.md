# R6: Durable grant pinning and monotonic revocation (local fixture)

**Status: OFFLINE LOCAL FIXTURE. LIVE_XI_CONNECTED remains false.**

R5 proved that operator permission must be separate from peer identity. R6 closes an important local-fixture rollback gap: after granting a peer, the receiving test process pins its grant ID and unchangeable authorization fields to SQLite. Revoking it creates a durable tombstone that cannot be undone merely by replacing the operator JSON file with an earlier allowed copy.

## Reproduce

    python -m pip install -r requirements-r3.txt
    python reference/python/demo_peer_r6.py
    python -m unittest discover -s tests -v

R6 starts a Phi fixture client and an Xi fixture server as **separate OS processes**. Both use disposable local signing/encryption keys. The demo:

1. Accepts a scoped, authorized signed-and-encrypted capsule; validates its receipt.
2. Refuses an edited expiration time using the **same** grant ID.
3. Proves that restoring the original authorized JSON still works before revocation.
4. Runs a **separate operator CLI process** that commits a revocation tombstone to SQLite before changing the grant JSON.
5. Restores the previously allowed JSON and confirms that the same ID still gets 403 grant_revoked.
6. Restarts the server using the existing SQLite grant ledger and confirms the restored old grant remains revoked.

The success result is **R6_MONOTONIC_REVOCATION_VERIFIED**, with **live_xi_connected:false**.

## Operator and server usage

When running the local R4/R5 fixture server, R6 is explicitly enabled by supplying both:

    --grant-file path/to/operator-grant.json
    --grant-ledger path/to/private-revocations.sqlite3

The R4 server **still binds only 127.0.0.1** and its fixed synthetic capsule endpoint. R6's grant ledger must be stored in an operator-controlled local directory, not a Git repo or shared network volume.

The owner-controlled revoke action is:

    python reference/python/xi_peer_r6_ledger.py revoke --grant-file path/to/operator-grant.json --ledger path/to/private-revocations.sqlite3

The CLI accepts only local fixture metadata, **never real Xi tessera keys**. It writes the durable revoked state *before* changing the editable grant file. If writing the JSON fails, restoring or retaining its old contents cannot reactivate the same grant ID.

## Security and truthfulness

- The ledger pins SHA-256 of the complete authorization policy **except** the mutable revoked boolean. Sender, recipient, room/stage, capability, time window, schema and grant ID are fixed after first authorized use.
- Authenticated identity (Ed25519) and permission (the grant) remain independent. Authorization is rechecked after decrypting and verifying each message, before reserving a message replay ID or sending a receipt.
- Durable SQLite transactions and explicit grant states refuse previously revoked IDs even across process restart or a rollback of the grant JSON.
- A new authorized grant must have a new grant ID. This design cannot verify that a new grant was issued by an authenticated human operator: it trusts the **local owner of the policy file**.
- **This is not cryptographically tamper-evident or rollback-proof against filesystem/database administrators.** Someone with permission to alter/delete the SQLite file, modify the code, or replace both state stores can defeat it. Genuine distributed revocation needs a secured authority, authenticated signing keys and durable replicated witness/checkpoints.
- If revocation occurs concurrently with an already admitted request, the request may complete. This does not provide in-flight cancellation, linearizable multi-host revocation, trusted time, malicious local process isolation, secure Windows ACL handling, or production DoS control.
- No live Room contract, official Xi TESSERA v4 codec, native .xi compiler, private memory, real Xi peer grants, remote endpoints or public posting are accessed. All packet contents and test keys are synthetic.

The remaining live integration work is tracked in [R3](XI_PEER_R3.md), [R4](XI_PEER_R4.md) and [Hunter's Table handoff](HUNTER_TABLE_HANDOFF.md).

**Capability does not equal authority. Ledger above ego.**
