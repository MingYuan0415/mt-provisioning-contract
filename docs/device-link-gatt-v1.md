# Device Link GATT profile v1

`profiles/device-link-v1.yaml` is the machine-readable source of truth for the
draft profile. UUIDs belong to Device Link v1 and must not be reused to change
the meaning of the provisioning v1 service.

## Link service

`link_state` exposes only protocol/profile versions and binding availability
before application authorization. It carries a serialized `PublicLinkState`
protobuf as the raw characteristic value: no framing header, no long read, no
Security 2 protection. The encoded value is at most 20 bytes so a single read
and notification work at ATT MTU 23. Its notification path is gated by the
same authorized-session check as events.

`PublicLinkState` fields:

- `protocol_major`/`protocol_minor`: Device Link protocol version;
- `profile_major`/`profile_minor`: frozen GATT profile version;
- `boot_id`: fresh nonzero value per boot; a changed value tells the client
  the device restarted;
- `state_flags`: `PUBLIC_LINK_FLAG_BINDABLE` while a pairing window is open,
  `PUBLIC_LINK_FLAG_BOUND` when a committed authorization record exists.

Value domain: every version field is a single-byte varint (0-127), `boot_id`
is nonzero, and `state_flags` is limited to the two defined low bits with all
higher bits zero. Within that domain the encoded value never exceeds 20 bytes;
a receiver must reject longer values and unknown flag bits.

`session_rx` accepts Write Requests only. `session_tx` uses indications only.
They become accessible after the current encrypted connection has been matched
to a Secure Connections bond in the NimBLE bond store. A connection flag alone
does not satisfy this admission rule.

`control_rx` accepts Write Requests only. `control_tx` uses indications for
responses and notifications for asynchronous events. Both require an
authorized application session associated with the current connection
generation.

The server permits one session or control transaction in flight. It sends the
next indicated fragment only after confirmation of the previous fragment. An
indication timeout or disconnect closes the Security 2 session.

## Transfer service

The static GATT database always contains the transfer service. Its access
callbacks reject use unless the connection is authorized and the transfer
capability is active. Transfer data uses Write Without Response and notification
with protocol credits; those rules are finalized with the transfer protocol.

## Permissions and CCCDs

Static characteristic permissions enforce link encryption where required.
Application authorization is implemented in project access callbacks and the
TX scheduler, not with NimBLE's SMP authorization flag.

NimBLE may restore bonded CCCDs before application authorization. A restored
subscription never authorizes transmission. The server suppresses control,
event, and transfer TX until authorization completes, then publishes a fresh
snapshot.

## ATT limits

The preferred ATT MTU is 498. With 251-byte Data Length Extension this produces
an ATT PDU plus four-byte L2CAP header of exactly 502 bytes, carried by two
maximum-size Link Layer data payloads. The optimization is not required for
correctness.

Write Request, Write Command, Notification, and Indication values are limited
to `ATT_MTU - 3`; Read Response values are limited to `ATT_MTU - 1`. All peers
must support the protocol at ATT MTU 23.
