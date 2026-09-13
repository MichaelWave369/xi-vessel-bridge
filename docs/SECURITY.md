# Security Model

## Threat model

Assume a peer can be buggy, compromised, stale, duplicated, reordered, replayed, or simply wrong.

## Required invariants

1. **Deny by default.** Unlisted operations do not run.
2. **Capability is not permission.** Discovery is descriptive only.
3. **No ambient authority.** Connection alone grants nothing beyond packet delivery.
4. **Idempotency.** Once a request ID has been accepted, replaying it must not execute the operation again.
5. **Fail closed.** Malformed, expired, unauthenticated, or policy-violating requests are rejected.
6. **No denial bypass.** A rejected request may not be reformulated into a substitute action unless a human or explicit local policy authorizes that new action.
7. **Bounded inputs.** Implementations set size, time, recursion, and resource limits locally.
8. **Pause is local.** Either architect can disable the bridge without cooperation from the peer.

## Replay handling

`request_id` is the idempotency key for an operation. Receivers SHOULD retain request IDs for at least the maximum retry/reconnect window they advertise. If the same request ID arrives again:

- same normalized request: return the cached status/result/receipt; do not execute again;
- different request body: reject as `request_id_conflict`; do not execute either body again.

## Authentication

v0.1 defines packet semantics but does not freeze a cryptographic profile. Production deployments MUST authenticate peers before exposing privileged capabilities. TLS with authenticated peer credentials and/or signed messages are plausible profiles, but selecting algorithms, key rotation, trust roots, and revocation is intentionally deferred.

Identity strings inside JSON are not authentication.

## Secrets

Never place API keys, access tokens, private keys, passwords, or reusable credentials in examples, capsules, receipts, repositories, or logs. Implementations should support secret redaction before persistence.

## Remote references

A URI or path received from a peer MUST NOT be fetched or opened automatically. Treat references as inert data until an explicitly permitted resolver validates scheme, host/path scope, size, and content.

## v0.1 forbidden shortcuts

- remote shell
- arbitrary eval/exec
- unrestricted local paths
- implicit network fetches
- credential forwarding
- permission inheritance from prior sessions
- retry by changing operation names
- executing a duplicate request ID twice
