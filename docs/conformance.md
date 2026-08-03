# Conformance

## Contract checks

A contract change passes only when Buf formatting and linting,
descriptor-backed fixture validation, validator unit tests, optimized-Python
validation, and the Buf breaking check all succeed. Generated language sources
and descriptor output are temporary and are never committed here.

The fixture validator checks canonical protobuf bytes and decoded fields,
malformed wire rejection, QR typing and Base64URL rules, event capability
gating, request/response mappings, scan normalization, cryptographic positive
and negative vectors, the stress-session workload, compatibility metadata, and
maximum frame sizes.

## Consumer checks

Each firmware and application consumer pins an exact contract commit and owns
its generator configuration and generated sources. A consumer must:

- decode every protobuf golden vector to the documented fields and reproduce
  the canonical bytes;
- reject malformed vectors and invalid QR payloads without coercion;
- execute every semantic case, including polling without encrypted events;
- preserve or safely ignore unknown protobuf fields and reject unknown enum
  behavior rather than guessing;
- prove that secrets are neither logged nor retained beyond their lifecycle.

Consumers implementing the development stress campaign must also pass the
[`stress-session`](stress-session.md) fixture. This workload is not a new
device capability and must not be advertised through the protobuf protocol.

## Interoperability

Contract checks alone do not establish interoperability. A known-good entry
requires the pinned Android and firmware commits to pass shared fixtures and
the real-device BLE discovery, Security 2, scan, connection, cancellation,
polling, optional-event, timeout, disconnect-recovery, and secret-handling
scenarios. The evidence entry is added after the tested contract release so it
can refer to immutable commits.
