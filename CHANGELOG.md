# Changelog

All notable contract changes are documented here. The format follows Keep a
Changelog and versions follow Semantic Versioning while the contract matures.

## [Unreleased]

## [0.1.1] - 2026-08-02

### Changed

- Made encrypted event delivery capability-gated and defined the complete
  polling fallback.
- Defined `proto-ver`, request/response invariants, identifier lifetimes, scan
  normalization, and snapshot field precedence.
- Replaced shallow fixture checks with descriptor-backed protobuf validation,
  strict QR checks, negative cryptographic vectors, wire limits, and validator
  unit tests.

### Clarified

- Defined generation zero as the latest completed scan result and required a
  final full snapshot refresh for polling clients.

## [0.1.0] - 2026-08-02

### Added

- Protocol Buffers v1 schema for provisioning and saved-network management.
- Protocomm Security 2 bootstrap and QR contract.
- AES-256-GCM event notification framing and recovery rules.
- Cross-platform semantic, protobuf, QR, and cryptographic fixtures.
