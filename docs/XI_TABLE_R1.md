# R1: Phi at the Table (staging adapter)

**State:** mock-only bridge prototype. Not a Xi integration, not a production security profile.

This rung answers a narrow question: can an explicit mention be authenticated, validated,
deduplicated and turned into an attributed, provenance-aware *mock reply draft* without
copying private conversations or giving either peer authority over the other?

## Proven and unproven boundaries

- The synthetic event schema is `xi.table.mention.mock.v1`. Hunter's real event/webhook
  format is **not established** by the published Creator Studio model/project APIs.
- The receiver processes only signed, timestamped `mention` events addressed to `Phi`
  in an optionally allowlisted room.
- Only the one message body crosses this adapter. No room history, attachments, model
  tokens, arbitrary tool calls or user memory are allowed in the event payload.
- Accepted events produce local **mock** reply drafts and receipts. They do **not**
  invoke Super Phi Vessel or publish any message to the Xi Room.
- Replies are not posted and do not prove remote or local model availability.
- Stored data contains event IDs, SHA-256 fingerprints, mock reply and receipt,
  but not message bodies. Transport logging is suppressed.
- Event IDs reserve durably in SQLite before processing. A duplicate event ID with the
  same exact body returns the cached result; differing bytes are rejected. After a
  crash with an in-progress record, this prototype does **not** retry automatically.
- SHA-256 proves byte identity, **not** authorship or truth. HMAC over the original
  request bytes authenticates a holder of the configured shared secret in this
  staging environment; it does not establish real Xi identities.

## Synthetic event contract (NOT Hunter's wire contract)

```json
{
  "schema": "xi.table.mention.mock.v1",
  "event_id": "b576f05e-7c5c-4e40-93dd-21dc68dfef70",
  "room_id": "local-staging-room",
  "message_id": "94d44e3b-c3d8-4265-befe-c3b2d157e1ce",
  "kind": "mention",
  "target_seat": "Phi",
  "sender": {"seat_id": "human-local", "display_name": "Local tester"},
  "body": "Hi @Phi!"
}
```

Signature: `X-Xi-Signature: sha256=<hex HMAC-SHA256>` of
`ASCII(X-Xi-Timestamp) + b"." + raw_utf8_body` using `XI_TABLE_WEBHOOK_SECRET`.
The signed timestamp is seconds since Unix epoch (five-minute tolerance).
The signature header and schema are **ours for staging**, not asserted Xi endpoints.

Only a single localhost HTTP route (`POST /v1/xi/events`) handles events.
`GET /healthz` reports mock status. The listener defaults to `127.0.0.1`
and writes its SQLite database to `.xi-table-state/events.sqlite3`.

## Run locally

In a private local shell, set the same generated secret for sender and listener:

```bash
export XI_TABLE_WEBHOOK_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python reference/python/xi_table_r1.py --room local-staging-room
```

In a second shell with the **same** exported secret:

```bash
python reference/python/send_mock_table_event.py
```

The sender intentionally refuses non-loopback destinations. Do not add the secret
to GitHub, logs, screenshots or chat. On Windows use your shell's equivalent for
setting an environment variable.

Run all conformance tests, including the existing neutral protocol:

```bash
python -m unittest discover -s tests -v
```

## Next agreements with Hunter

1. Get consent and a documented staging-only Table event format, posting interface,
   host allowlist, seat identity model and webhook verification scheme.
2. Confirm a safe mechanism for delivering events from the Table without exposing
   private history or running an unsolicited public network listener.
3. Design a true Phi runtime adapter behind a strict allowlist. Never turn
   message text into shell, file, browser, or repository privileges.
4. If real replies become possible, require downstream idempotency before claiming
   exactly-once posting; add a bounded outbox and manual recovery procedure.
5. Add controlled context grants, revocation, operator pause, monitoring and
   retention limits, plus a test room owned/authorized by Hunter.

**Do not deploy this as a public webhook or connect to Hunter's production Room yet.**
