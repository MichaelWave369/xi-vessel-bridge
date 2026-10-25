# R15: PhiOS / GitPorch ↔ Xi Offline Porch Adapter

**Status:** LOCAL READ-ONLY EVIDENCE FIXTURE. `LIVE_XI_CONNECTED=false`.

The first crossing deliberately has **no sockets, credentials, remote execution, live replication, push/pull, automatic writes, or filesystem mutations**. It reads an operator-selected directory, a quarantined Xi offline bundle, or a locally provided Phi-Xi relay JSON message, then emits bounded JSON observations to stdout.

This is complementary to R3–R14; it does **not** replace `xi.exchange.v1`, grant review, or transport/policy requirements. In particular, Hunter's separate `PhiXi.Relay.v0.1` is a distinct signed message grammar. Never relabel it as an authenticated bridge packet.

## Inputs and boundaries

| Input | What is verified | What is NOT established |
|---|---|---|
| An explicitly chosen GitPorch/PhiARK directory | SHA-256 of regular files, names and sizes, deterministic inventory digest | Consent to share file bytes; runtime reachability |
| Xi offline `tar.gz` with `README_PINS.json` | All listed byte sizes and SHA-256, total coverage, bounded member/path/type checks | Independent author identity, code safety, deployability, real failover |
| `PhiXi.Relay.v0.1` JSON + **out-of-band** pinned peer public key | Ed25519 signature, timestamp window, schema, sender pin, bounded integrity for inline delivery | Permission to process remote requests, long-term replay safety, real Xi authorization |

No unpacking or execution of Hunter's supplied bundle is done. Archive traversal, links, duplicate members, unlisted files and oversized members fail closed. SQLite, private keys and model weights are not accessed automatically.

## Running locally

Requires Python 3.12+; `inspect-relay` uses the cryptography package already specified in `requirements-r3.txt`. Neither `inventory` nor `audit-bundle` uses that dependency.

```sh
python reference/python/phi_xi_porch_adapter.py inventory --root /your/explicit/export/folder
python reference/python/phi_xi_porch_adapter.py audit-bundle --archive /path/to/xi_offline_whole_home_bundle_v9.tar.gz
python reference/python/phi_xi_porch_adapter.py inspect-relay --pins /private/local/public-peer-pins.json --messages /path/to/relay-messages.json
python -m unittest discover -s tests -p 'test_phi_xi_porch_adapter.py' -v
```

Run inventory against a **small, nonsecret, explicitly prepared export directory** rather than your entire home directory or GitPorch service root. Its JSON output lists relative filenames and hashes, and should be reviewed before even optionally sharing it.

Example **format only** of `public-peer-pins.json`:

```json
{
  "peers": [
    {
      "name": "peer whose identity I verified separately",
      "ed25519": "ed25519:<base64 of 32-byte authenticated public key>"
    }
  ]
}
```

The angle-bracket text is a placeholder, not a usable pin. Do not import the sender's `from` value as an authority by itself. Authenticate the peer key by a separate agreed channel first. Keep pin files in operator-controlled local storage, not in this repo.

Messages may be a single JSON object or an array (maximum 64). Only `announce`, `deliver` with complete inline bytes, and `receipt` are examined. Signed `request` packets are **always refused**; a pointer-only LightBridge delivery is never counted as content-verified. Checks enforce a ±10-minute message age and detect repeated IDs **within that invocation only**. Never infer a persistent anti-replay ledger, trust establishment, or room authority from these reports.

## Interpretation and R16 gates

- Inventory receipts are local observations, not release manifests or permission grants.
- SHA-256 matches the supplied archive's own manifest; that is a consistency check, **not an authenticating signature**.
- Ed25519 messages require independently pinned sender public keys; a valid signature merely proves possession of the corresponding key.
- "Two-Porch Mutual Mirror", offline/active-active failover, and Room-note delivery remain **proposals or simulations** until verified across isolated, authenticated systems.
- `xi.exchange.v1` authorization is still governed by local grants, immutable request bindings, and R10–R14 independent evidence gates.

**Before live/bi-directional transport:** establish human-approved scope, confirmed cross-peer identity pins, authenticated channel, durable restart-proof replay protection, bounded content consent, independent two-machine disconnect/reconnect tests, and operator pause/revoke controls on both sides. None is activated by this change.
