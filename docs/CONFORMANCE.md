# Conformance

## Levels

### Fixture-conformant
An implementation can parse the canonical examples and preserve required envelope, capsule, request, result, and receipt fields.

### Handshake-conformant
An implementation completes the sequence in `HANDSHAKE.md` and passes the replay/denial requirements.

### Production-conformant
**Not defined in v0.1.** Production authentication, signing, revocation, transport hardening, audit retention, and operational policy remain open work.

## Canonical test vector

`examples/sample-capsule.txt` is exactly 48 bytes and has SHA-256:

```text
231f6819dd40525827715ee0b893c1273b745a83a1f45a620c5aa6db40ddf4bb
```

The canonical operation is `artifact.sha256`.

## Run locally

From the repository root:

```bash
python reference/python/bridge_demo.py
python -m unittest discover -s tests -v
```

No third-party Python dependencies are required.

## Compatibility reporting

When another implementation reports compatibility, record:

- implementation name/version
- protocol version
- transport used
- capability fixture used
- capsule digest
- request ID
- result status
- replay result
- denial test result
- known deviations

Do not report "production secure" based only on this suite.
