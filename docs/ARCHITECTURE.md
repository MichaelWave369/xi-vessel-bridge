# Architecture

## Purpose

Xi Vessel Bridge is a federation boundary, not a shared brain. Each peer keeps its own governance, runtime, storage, models, tools, and failure modes.

```text
Super Φ.Vessel                         ForgeCore
┌──────────────────┐                 ┌──────────────────┐
│ Human Authority  │                 │ Human Authority  │
│       ↓          │                 │       ↓          │
│ Crane Fly Router │                 │ Local Router     │
│       ↓          │                 │       ↓          │
│ Xi Bridge Gate   │<===============>│ Xi Bridge Gate   │
└──────────────────┘ authenticated   └──────────────────┘
                    narrow boundary
```

The bridge can expose *possibilities*. It cannot manufacture authority.

## Components

### Packet envelope
Carries identity, message/session/request IDs, type, timestamps, and payload.

### Capability advertisement
A peer states selected capabilities it is willing to reveal. Absence means unavailable. Advertisement alone is never authorization.

### Capsule exchange
A capsule carries content metadata and provenance. A receiver may accept, deny, quarantine, or ignore it according to local policy.

### Tool request gate
The receiver evaluates the named operation against local policy. A bridge implementation MUST NOT translate a denial into a different operation in order to obtain an equivalent result.

### Receipt ledger
Every accepted tool request produces a receipt. A denied/unavailable request should also be receipted when the implementation can do so safely. Receipts are evidence of what the receiver reports happened; they do not grant authority.

## Authority boundary

Remote packets have **zero ambient local authority**. They are inputs to a local decision process. Filesystem paths, model names, tool names, repository names, and URLs contained in a packet are data until local policy explicitly resolves them.

## Evolution

v0.1 proves one read-only round trip. Later versions may add authenticated signing profiles, worktables, negotiated model access, or richer capsule types. Those additions must preserve the v0.1 authority boundary unless a new major protocol explicitly states otherwise.
