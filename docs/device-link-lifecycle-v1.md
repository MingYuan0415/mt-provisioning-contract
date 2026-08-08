# Device Link lifecycle v1

BLE ACL, Secure Connections bond, peer identity, Security 2 session, and
application authorization are separate facts. Firmware must not infer one from
another or depend on callback arrival order.

## Connection facts

For each connection generation firmware tracks:

- ACL connected;
- link encrypted;
- Secure Connections bond verified;
- peer identity known and matched;
- bootstrap or long-term Security 2 authenticated;
- local confirmation completed;
- authorization record committed;
- session/control/event CCCD state.

Every asynchronous callback carries or is checked against the current
generation. Late callbacks from a disconnected generation have no effect.
`READY` is a derived state, not a callback event.

## Admission

An unknown peer can pair only while the device is in a locally opened pairing
window. Additional ACLs are rejected. Session access requires encryption and a
verified Secure Connections bond. Control and transfer access additionally
require a current authenticated application session matching the committed
authorization record.

Restored CCCDs remain transport facts only. They do not bypass application
admission. After authorization the device publishes a full snapshot before
incremental events.

## Identifier scope

- `boot_id` is a fresh nonzero random value for each boot. Both directions
  carry it; a receiver rejects an envelope whose boot ID does not match the
  active boot and closes the session.
- `request_id` is nonzero and unique within an application session; it provides
  correlation, not idempotency.
- `event_sequence` is nonzero and monotonic within a boot. A new boot ID resets
  its interpretation.
- operation IDs are nonzero and unique within a boot and are interpreted with
  the boot ID.
- transfer IDs identify one transfer. Device Link v1 test-file transfer does
  not resume across device reboot.
- connection generation is internal and never appears on the wire.

Envelope flags are a repeated set: each value appears at most once, unknown
values are rejected, and `ENVELOPE_FLAG_RECOVERY_QUERY` is the only defined
flag in v1. Sequence or identifier wrap closes the affected session before
reuse.

## Request and event semantics

- `request_id` is unique within a session. A repeated request ID for the same
  session is rejected with `LINK_ERROR_CONFLICT`; the client must use a fresh
  ID or recover through a query.
- `event_sequence` starts at 1 for each boot, increases monotonically, and
  never wraps. Reaching the maximum value stops event publication for the
  rest of the boot; a new boot is required to resume events. A client that
  observes a changed `boot_id` discards all session state.
- Event publication starts only after subscription is established. The
  subscribe response carries an atomic snapshot captured at that moment in
  `EventSubscription.snapshot`, and `sequence_baseline` equals that snapshot's
  `event_sequence`. Incremental events then start at `baseline + 1`, so no
  event is lost between the snapshot and the first notification.
- A snapshot is generated atomically with the state it summarizes; the
  `event_sequence` baseline, subscription material, and snapshot are produced
  in one consistent view.
- Response caches are scoped to the connection and characteristic and are
  cleared on read, disconnect, timeout, or generation change.

## Android consumer requirements

The application persists an opaque device authorization ID and a wrapped
long-term credential. It treats Android's bond and address as system transport
state, not as application authorization. It preserves a prepared credential
after an ambiguous Commit result and tests it on reconnect.

When a Commit response is lost, the recovery sequence is:

1. Reconnect and re-handshake with the preserved long-term credential (the
   prepared application password).
2. Send `GetAuthorization` with the prepared credential ID and the
   `RECOVERY_QUERY` envelope flag on the session channel.
3. Compare the returned credential ID with the prepared one. Equal: persist
   the returned `device_authorization_id` and continue. Different or an error:
   the prepare was replaced or never committed; do not retry the old Commit
   and start a fresh locally confirmed binding.

The app must not use the session channel for authorization-gated business
requests, and must not subscribe to encrypted events in v1 (they are not
advertised; polling `GetLinkSnapshot` is the supported path).

Android RPA resolution, Companion Device association, background execution,
and vendor GATT recovery are deliberately not marked verified by this device-
focused P0 contract. They must be reviewed when the Android consumer is
implemented.
