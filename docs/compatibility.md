# Compatibility

Wire major 1 is represented by package `microtech.provisioning.v1` and
`ProvisioningRequest.protocol_major=1`. A different major is rejected before
dispatch. Minor compatibility is feature-negotiated through `Capabilities`.

Compatible changes may add optional message fields, new request/response arms,
new enum values, and new feature flags. Implementations must preserve unknown
protobuf fields where their runtime supports it and treat unknown enums as an
unsupported capability rather than guessing.

Incompatible changes include field-number reuse, field type changes, enum value
reinterpretation, different encryption/AAD construction, and changed operation
success semantics. Those changes require a new protobuf package major.

Consumers pin an exact contract Git commit. A combination becomes `verified`
only after Android and firmware pass the shared fixtures and the real-hardware
acceptance scenarios. Updating a submodule pointer alone is not verification.
