# R10: Xi partner staging contract intake gate

**Status: a read-only, offline review aid. NOT live Xi access, transport integration, authenticated document verification, or permission to post to the Table.**

R3–R9 exercise cryptography, local transports, grants, public evidence and expected signing-key pins with **synthetic peers**. The remaining limitation is not solved by another locally invented endpoint: we need Hunter's real **approved staging interface and trust parameters**.

R10 provides a strict machine-readable starting point and a no-network validator. It transforms a proposed partner contract into an **actionable, redacted evidence-gap report**. It deliberately does not try a remote API call or auto-authorize any operation.

## Use it with Hunter

Generate an *unfilled* candidate, safe for review:

    python reference/python/xi_partner_r10.py template --out xi-partner-candidate.json

Inspect it without sending anything across the network:

    python reference/python/xi_partner_r10.py inspect --file xi-partner-candidate.json

To require all necessary *fields* to be filled (still NOT partner-approved):

    python reference/python/xi_partner_r10.py inspect --file xi-partner-candidate.json --require-complete

An incomplete candidate produces `R10_INTAKE_INCOMPLETE` with the missing evidence fields. The `--require-complete` command returns status 2 when items remain absent or unverified.

Run an explicitly fictitious fixture as a safe smoke test:

    python reference/python/xi_partner_r10.py synthetic --out xi-synthetic-candidate.json
    python reference/python/xi_partner_r10.py inspect --file xi-synthetic-candidate.json --require-complete

This reports `R10_SYNTHETIC_SHAPE_VERIFIED`. The synthetic example uses a reserved, non-routable .invalid hostname and **fabricated** document hashes. It is never permission to connect to a real server.

## What Hunter can supply (no secrets)

The candidate includes these sections, all with fixed fields and bounds:

- Peer identity labels and staging room/seat labels.
- Transport mode (for now **outbound polling only**, avoiding a public webhook) and documented HTTPS event URL. Reply URL only if there is an independently authorized `table.reply` scope.
- Authentication *mechanism*, scoped capability **names**, and the SHA-256 of the public grant/revocation **specifications**, not the token or credential.
- Native message media type, authoritative Xi schema document SHA-256, actual canonical signing-byte convention, and genuine .xi/TESSERA version.
- Receipt request-ID fields, deduplication guarantee, size and timeout bounds.
- Digests of a verified transport specification and redacted event/reply examples, plus an out-of-band partner signing-key fingerprint record. No real secret keys.
- SHA-256 of a **human approval record** in the appropriate local system; the hash is only a reference, not proof that such an approval exists.

A candidate must never include raw bearer tokens, authentication headers, private keys, private Room history, passwords, or executable tool requests. Do not copy the private pickup file or its contents into this repository, an issue, or chat.

## What the validator rejects

- Unknown sections or version; secret-like values and fields.
- Admin, shell, filesystem-write, or undisclosed capabilities; duplicate scopes.
- HTTP instead of HTTPS, loopback and private IP URLs, redirects, URL-embedded credentials or query strings, non-official placeholder hosts in staging candidates.
- Unsolicited inbound webhook mode; a reply URL without `table.reply` scope; reply permission without explicitly documented evidence.
- Missing and all-zero document hashes, malformed schemas, implausible limits and missing idempotency semantics.

## Honesty about output

A syntactically complete, *partner-provided* staging contract returns **R10_STAGING_CANDIDATE_REQUIRES_JOINT_REVIEW**, never `LIVE_XI_CONNECTED`. This validator does **not** authenticate the SHA-256 source documents, confirm key fingerprints against Hunter personally, verify actual Xi permission or execute any probe.

Before the first live crossing, human operators on **both sides** must separately verify each document and public key, approve the exact room/seat/action, choose a private credential channel, configure revocation, and witness a real transaction plus receipt. The live adapter must be built **from those verified real interfaces**, not the synthetic examples.

For the remaining exact questions, see [R7 partner contract request](XI_R7_CONTRACT_REQUEST.json) and [Hunter handoff](HUNTER_TABLE_HANDOFF.md).

**Capability does not equal authority. Ledger above ego.**
