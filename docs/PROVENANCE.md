# Provenance

Xi Vessel Bridge treats provenance as part of the artifact, not decorative metadata.

## Minimum capsule provenance

A capsule carries:

- `author`
- `source`
- `version`
- `created_at`
- `intended_use`
- optional `license`
- optional `parent_sha256` when derived from a prior artifact

The content block separately records media type, encoding, byte size, and SHA-256.

## Preservation rule

Forwarding or transforming a capsule MUST NOT silently replace its original provenance. A transformed artifact should receive new provenance and link to its parent digest.

## Hashes

SHA-256 proves byte identity, not truth, authorship, safety, or authorization. A matching hash means the bytes match the referenced bytes. Humanity has enough problems without asking hashes to have opinions.

## Receipts

Receipts bind an execution claim to:

- `request_id`
- operation
- receiver identity
- status
- recording time
- execution count
- relevant artifact digest when available

A receipt is evidence emitted by a receiver. Cryptographic non-repudiation is not claimed until a future signed-receipt profile is frozen.
