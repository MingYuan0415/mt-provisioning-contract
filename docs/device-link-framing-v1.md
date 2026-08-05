# Device Link framing v1

Session and control characteristics use the same application fragmentation.
Security 2 handshake protobuf messages are reassembled before they are passed
to Protocomm. Protected application messages are encrypted before they are
fragmented.

```text
protobuf -> Security 2 -> fragmentation -> GATT
GATT -> reassembly -> Security 2 -> protobuf
```

## Fragment header

Every characteristic value starts with this eight-byte header:

| Offset | Size | Field | Encoding |
| --- | ---: | --- | --- |
| 0 | 1 | version | unsigned, value 1 |
| 1 | 1 | flags | `START=0x01`, `END=0x02` |
| 2 | 2 | frame ID | unsigned little-endian, nonzero |
| 4 | 2 | total length | unsigned little-endian |
| 6 | 2 | offset | unsigned little-endian |

Unknown flag bits are invalid. `total length` is the complete message after
Security 2 processing and before fragmentation. It is identical in every
fragment. The GATT value length determines the fragment payload length.

The first fragment has `START`, offset zero, and a nonempty payload. The final
fragment has `END`, and `offset + payload length` equals total length. A
single-fragment frame has both flags.

## Reassembly

Each RX characteristic has one reassembly slot per connection generation.
Fragments are normally sent in increasing offset order. An exact duplicate of
the most recently accepted fragment is accepted without appending it again.
A duplicate with different bytes, a gap, overlap, zero frame ID, changed total
length, excess length, or unexpected `START` is rejected.

Disconnect, timeout, connection-generation change, or protocol error clears
the slot and closes any associated Security 2 session. A complete frame is
delivered exactly once.

Fixed timeouts:

- reassembly idle timeout: 5000 ms without a new fragment clears the slot;
- indication confirmation timeout: 2000 ms per outstanding indication,
  measured from the moment each fragment is submitted; a timeout on any
  fragment ends the transaction and closes the Security 2 session.

Both values are part of the contract and must appear in the same form in the
fixtures and in the firmware assertions.

The 16-bit `total_length` field bounds the largest representable frame at
65535 bytes. Per-channel limits are a separate layer: session messages are
limited to 1024 bytes and control messages are provisionally limited to 4096
bytes until the firmware resource campaign freezes the final limit. Both
layers are enforced by the consumer; the reference reassembler enforces the
16-bit field and caller-provided capacity. Transfer data does not use a
control reassembly slot.

## Reliability

Every RX session/control fragment uses Write With Response. Every TX
session/control response fragment uses indication, one at a time. The next
request cannot start until the final response indication is confirmed.

An indication timeout or ambiguous response ends the Security 2 session. A
client establishes a new session and queries snapshot or operation state; it
does not retransmit a state-changing request in the old session.

Events use notifications with an independent authenticated event sequence.
Sequence gaps are recovered with a full snapshot.

Framing-level errors occur before any envelope or request ID is available.
They are reported with ATT error responses or disconnection, never as a
protected `LINK_ERROR_MALFORMED_FRAME` response. That error code is reserved
for application payload framing discovered after decryption, when a request ID
can still be echoed.

## MTU boundaries

| ATT MTU | GATT write/notify/indicate value | Framing payload |
| ---: | ---: | ---: |
| 23 | 20 | 12 |
| 185 | 182 | 174 |
| 498 | 495 | 487 |

The sender derives these values from the negotiated ATT MTU. A client-reported
MTU is never trusted as protocol state.
