# Compatibility

Contract release 0.1.1 implements protocol 1.0. The repository release and
wire protocol versions are independent: protocol major 1 is represented by
package `microtech.provisioning.v1`, `ProvisioningRequest.protocol_major=1`,
and `Capabilities.protocol_version={major:1, minor:0}`. A different request
major is rejected before dispatch. Optional behavior is feature-negotiated
through `Capabilities` and `proto-ver`.

Compatible changes may add optional message fields, new request/response arms,
new enum values, and new feature flags. Implementations must preserve unknown
protobuf fields where their runtime supports it and treat unknown enums as an
unsupported capability rather than guessing.

`FEATURE_ENCRYPTED_EVENTS` is optional. Its presence must agree with the
`mt-events-v1` `proto-ver` capability and the event characteristic. A client
that does not recognize a feature ignores it; a client never infers support
from an extra GATT property.

Incompatible changes include field-number reuse, field type changes, enum value
reinterpretation, different encryption/AAD construction, and changed operation
success semantics. Those changes require a new protobuf package major.

Operation IDs and snapshot or scan generations are scoped to one device boot.
They are nonzero, monotonically increase, and are not reused during that boot.
They may restart after reboot, so clients compare ordering only within a
single boot. Background policy work uses operation ID zero and is never
returned by `GetOperation`.

Consumers pin an exact contract Git commit. `known-good.yaml` contains a list
of tested combinations. A combination becomes `verified` only in a later
contract commit, after Android and firmware pass the shared fixtures and the
real-hardware acceptance scenarios. Updating a submodule pointer alone is not
verification.
