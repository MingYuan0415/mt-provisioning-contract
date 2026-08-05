# Changelog

All notable contract changes are documented here. The format follows Keep a
Changelog and versions follow Semantic Versioning while the contract matures.

## [Unreleased]

### Added

- Added the draft Device Link v1 protobuf package and static GATT profile.
- Defined device-focused framing, Secure Connections binding, application
  authorization, recovery, and lifecycle requirements.
- Defined the public `PublicLinkState` wire for unauthenticated `link_state`
  reads and notifications, bounded to 20 encoded bytes.
- Defined the advertising and discovery contract: Flags, 128-bit Service Data
  with advertising version, bindable flag, and a fresh per-window 24-bit
  discriminator, plus the `MT` short name.
- Frozen reassembly idle (5000 ms) and indication confirmation (2000 ms)
  timeouts, duplicate request-ID rejection, boot-scoped event sequences
  without wrap, and atomic snapshot generation.

## [0.1.2] - 2026-08-04

### Added

- Defined the Security 2 `GetSnapshot` stress-session workload used by the
  firmware concurrency campaign.
- Added a strict stress-session fixture and validator coverage without changing
  the protobuf wire schema.

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
