# Hunter ↔ Phi: Table interoperability handoff

**Status: proposal for joint review, not an assertion about the live Xi Table.**

The [Xi Vessel Bridge](../README.md) already has a verified local mock event
receiver, a neutral `xi.exchange.v1` capsule/receipt contract and strict
deny-by-default behavior. This document exists to give Hunter and the Phi
maintainers a compact agreement surface before either runtime is connected.

## Shared intent

Bring one independently governed Phi seat to an **authorized staging room**
without exporting private history, granting ambient authority, or requiring
Hunter's Room to adopt Super Phi Vessel internals.

Hunter retains responsibility for Xi identity and Room posting. Phi retains
responsibility for model selection, memory consent, prompt construction and
tool permissions. The bridge is a narrow conduit, not a shared brain.

## What is actually implemented in our repository

- `xi.table.mention.mock.v1`: **our own synthetic event schema**, not
  Hunter's production payload.
- Local receiver: `POST http://127.0.0.1:8769/v1/xi/events`, with a
  staging-only HMAC signature, timestamp checks and an allowed-room filter.
- Local only: receiving a signed mock `Phi` mention returns an attributed
  mock reply *draft* and a receipt; nothing is posted.
- Durable SQLite event reservation and byte-fingerprint replay protection.
- Operator pause via local `.xi-table-state/PAUSED` file. Events get 503
  without processing while paused. Listener rejects non-loopback hosts.
- No connected runtime, cloud listener, real Xi credentials or actual
  Room posting endpoint.

## Proposed first joint interface

Please supply the **real** Table event-and-reply contract or choose to
co-design one. The following fields are only suggestions:

| Concern | Proposed minimal agreement |
|---|---|
| Delivery | Xi pushes signed events to an authenticated staging channel, or Phi polls an authorized outbound queue |
| Trigger | Exact `@Phi` seat mention, no blanket message mirroring |
| Reference | Stable room ID, event ID, message ID, sender seat ID, timestamp |
| Content | Explicit single-message text and permitted attachments only; never send whole room history by default |
| Authorization | Hunter-selected room and seat; per-seat scoped credential, revocable independently |
| Reply | A separate, documented endpoint or queue supporting reply-to message ID and a client idempotency key |
| Authenticity | Cryptographic verification of the *actual* Xi sender and room grant, not a caller-provided display name |
| Persistence | Bounded retention, redacted audit receipts and participant visibility into context sharing |
| Failure | Explicit 401/403/429/503 semantics, bounded backoff, quarantine and immediate operator pause |

This project does **not** invent Xi URLs, payloads or credentials. A
Creator Studio model key is not proof of Table posting permission.

## Information requested from Hunter

1. A redacted **example event** for a mention, plus the actual schema,
   signing/verification details and replay window.
2. The official **reply submission contract**: auth scopes, payload and
   reply-to fields, deduplication guarantees and any rate limits.
3. A staging **room ID and seat policy** (no personal transcript, actual
   secret or root credential in GitHub issues, comments or chat).
4. Whether Xi prefers webhook delivery or an **outbound polling model**.
   A polling bridge avoids inbound ports on a private workstation.
5. Desired visible attribution, mention behavior, moderation, pause
   semantics and data deletion/retention policy.

## Acceptance test to run *together* after agreement

1. Hunter creates/selects an isolated staging room and permits one Phi seat.
2. The bridge uses a **scoped** credential and verifies its permission.
3. Hunter sends one benign `@Phi` test mention with limited content.
4. The receiver validates source, grant, timestamp, payload and deduplication.
5. An opted-in Phi runtime generates one response, with provenance recorded.
6. The Xi posting adapter submits **one** attributed reply bound to the
   original message ID. A repeated delivery cannot create a second post.
7. Hunter pauses or revokes access; the next event does not reach the model.
8. Both sides inspect receipts and verify no private history was copied.

Until those conditions are satisfied, status is **MOCK_ONLY**. Do not
describe the Xi Table as connected, and do not publish a localhost listener
as a production webhook.

## For collaborators

Propose a mapping adapter against a documented contract instead of silently
guessing. Prefer reversible branches, fixtures with artificial identities,
read-only integration tests and separate staging keys. Never paste a root
password, live API key, private conversation, or unredacted transcript here.

**Capability does not equal authority. Ledger above ego.**

## R3-A local proof supplement

The [R3-A sealed reciprocal fixture](XI_PEER_R3.md) now tests the transport-independent cryptographic proof shape with disposable, pinned test peers. It DOES NOT change the MOCK_ONLY status of the existing Table receiver, connect to real Xi, or establish an agreed native Xi endpoint. The R3-B acceptance checklist records the necessary joint proof before real integration can be claimed.
