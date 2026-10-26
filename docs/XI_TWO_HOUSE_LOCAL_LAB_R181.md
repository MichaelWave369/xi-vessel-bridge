# R18.1 · Two-House Local Simulation Lab

**Status: `R18_1_TWO_HOUSE_LOCAL_SIMULATION_PASS` (when tests pass), NOT A REAL Xi TWO-HOST CROSSING.** This is a PHI-authored offline fixture. It does not contact or represent Hunter's infrastructure and cannot promote R17/R18 external gates.

## Run the lab

```sh
python -m pip install -r requirements-r3.txt
python reference/python/xi_two_house_r181.py demo
python -m unittest discover -s tests -p 'test_xi_two_house_r181.py' -v
python -m unittest discover -s tests -v
```

The `demo` command generates two separate ephemeral Ed25519 private keys in a temporary folder, starts two separate **local worker processes** using stdin/stdout rather than a network server, and gives each worker its own private SQLite request ledger, R16 challenge ledger, state directory and explicitly opted-in allowlist. No secrets or private key bytes enter output or GitHub artifacts. No persistent installation or external network connection is required.

Each simulated peer is named `phi-sim` or `xi-sim`. The second name is **just a fixture label**, not a statement that Xi's actual software, native schema, human operator or key participated.

## Protocol rehearsal in exact order

1. The PHI-sim house creates a signed R16 challenge; Xi-sim verifies and signs its proof; PHI-sim consumes it once and issues a signed receipt; Xi-sim verifies the receipt.
2. The reverse R16 challenge/proof/receipt exchange occurs, giving **each** process an inbound and outbound proof of possession against its locally pinned fixture key.
3. PHI-sim emits one Ed25519-signed `xi.exchange.v1`-**shaped** `tool.request` addressed to Xi-sim. The only permitted operation is `artifact.sha256`, the only permission is `read_only`, and `dry_run=true` is mandatory. The `input` contains exactly the immutable R18 `synthetic_public` fixture. Request IDs, message IDs and session IDs are canonical UUIDs; date-time fields carry a 45-second TTL.
4. Xi-sim verifies sender signature, room, session, recipient pin, timestamp, exact envelope/payload fields, its own bilateral R16 state, its locally opted-in allowed operation and the **literal** R18 fixture bytes. Only then does it generate a signed `tool.result` with a `receipt.schema.json`-shaped result (request ID, operation, timestamp, execution count 1 and digest). A separate durable SQLite transaction consumes the request ID **before the result is returned**. Duplicate requests are not re-run, including after worker restart.
5. PHI-sim verifies the signed result and that its request ID, original signed request hash, peer key, digest, operation and receipt agree. Confirmation is also one-time.
6. The direction is reversed: Xi-sim requests the same explicitly allowed synthetic digest from PHI-sim. These are two separately governed local receive policies, not one shared admin policy.
7. Restart Xi-sim, perform a **fresh** bilateral handshake, and ensure the previously accepted PHI request remains rejected.
8. Check signed packet tampering and permission escalation are rejected, then locally pause Xi-sim, demonstrate immediate refusal, resume by clearing only its own pause marker, revoke the pinned fixture key, restart, and show the revocation persists.

`demo` returns a **redacted JSON status** with process count 2, physical host count 1, R18 fixture fingerprint and pass/fail control booleans. It never emits private keys, complete signed messages, actual endpoints or remote receipts.

## What is and isn't compatible

The signed application messages use the fields and message types from the existing `spec/xi.exchange.v1.schema.json` contract and exercise existing `spec/tool-request.schema.json` and `spec/receipt.schema.json`-shaped payloads. They add a **local fixture-only Ed25519 profile** to the optional `auth` and `signature` envelope fields. This is **not** a jointly reviewed native Xi cryptographic protocol, network transport mapping or final R18 connector. There is no mTLS, no production network authentication, no external identity proof, and no authorization to exchange private information.

The handshake itself reuses **R16's separately named fixture grammar**, rather than silently pretending that R16 packets are Xi-native traffic. Only two **independent local processes** execute; both are on **one physical machine**. CI success proves the mock lab, not a two-host or two-operator field exercise.

The test suite also covers wrong sender/recipient keys, omitted proof, expired messages, unknown session, modified fixture bytes, changed signature fields, extra privilege fields, unapproved receiver policy, altered result receipt, missing request binding, duplicate result, local pause, durable revocation, arbitrary worker commands and session reset on restart.

## Protection boundaries

- `--allow-digest` is a **local simulation permit** provided when the fixture worker starts. It is not remote consent or a persistent grant to a real agent.
- Neither worker provides a socket listener, repo access, shell tool endpoint, external network API, filesystem mirror, key export, model call or arbitrary payload intake route.
- Local workers hold their ephemeral fixture keys separately; the coordinator knows only public key identifiers and shared test session, except during the private-key generation step before workers launch.
- A crash after a request ID is committed can leave its reply undelivered. The receiver still refuses redelivery rather than risk duplicate execution. That is a safe **at-most-once** demo, not a production guaranteed-delivery system.
- The pause marker and revocation ledger are per-house. Pausing one doesn't automatically modify the other. All data is lost after the temporary demo concludes, apart from redacted CI evidence.
- `python reference/python/xi_two_house_r181.py require-live` always exits **2**. No local JSON field, CI badge or simulation receipt can independently authorize Xi operations.

## Required future real Xi pilot evidence

Still blocked: independently authenticated public-key identity binds for both operators, jointly reviewed Xi-native operation schemas, an encrypted authenticated actual two-host transport, narrowly and separately approved permissions, data consent, signed independent receipts, two-machine replay and revocation checks, loss/reconnect behavior and a mutually agreed kill switch. A successful local rehearsal **cannot** complete any of these external gates.

**Ledger above ego. Two houses, two key rings, one simulated byte digest.**
