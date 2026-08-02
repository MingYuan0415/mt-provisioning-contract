# Contributing

1. Change behavior documentation and schema in the same commit.
2. Never reuse removed field numbers or enum values; reserve them instead.
3. Add or update fixtures for every externally observable behavior change.
4. Run formatting, lint, breaking-change, and fixture validation before review.
5. Do not commit generated C, Kotlin, Java, or build output.
6. Keep `VERSION`, `CHANGELOG.md`, protocol fixtures, and compatibility metadata
   consistent.
7. Record a verified combination only in a later commit that can reference the
   immutable contract, firmware, and application commits it tested.

Backward-compatible optional fields and enum additions increment the minor
version. Removing or reinterpreting existing wire behavior requires a new
protobuf package major such as `microtech.provisioning.v2`.
