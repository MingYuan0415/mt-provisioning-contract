# Device Link session transport v1

This document defines how the session and control characteristics carry
Protocomm Security 2 (profile `protocomm_security_version=2`, patch 1). It
complements the frozen fragmentation contract
(`docs/device-link-framing-v1.md`): after reassembly every message begins with
a one-byte transport type that disambiguates the Security 2 handshake from a
protected application message.

## Transport type

| Type | Name | Body |
|---|---|---|
| `0x00` | handshake | Protocomm Security 2 handshake wire (see below) |
| `0x01` | protected | AES-GCM ciphertext of a Device Link `Envelope` |

The type byte is part of the reassembled message, after the eight-byte
fragment header. It is not inside the fragment header. Unknown type bytes are
rejected and close the Security 2 session.

## Handshake (`0x00`)

The body is the Protocomm Security 2 handshake wire as implemented by the
ESP-IDF `protocomm` component: a `SessionData` protobuf (`session.proto`)
with `sec_ver = 2` and `proto` set to `Sec2Payload`, carrying
`S2SessionCmd0`/`S2SessionCmd1` from the client and `S2SessionResp0`/
`S2SessionResp1` from the device. The device answers handshake messages with
type `0x00` on `session_tx`.

- Accepted only on `session_rx`. A handshake body on `control_rx` is rejected
  and closes the session.
- A `SessionData` that fails to parse, carries `sec_ver != 2`, or selects the
  wrong payload type is rejected and closes the session.
- A handshake arriving at any time replaces the current Security 2 session
  (the Protocomm security instance keeps one session). When a protected
  transaction is in flight, the replacement aborts it (see the session
  lifecycle); this is the deterministic recovery path after an ambiguous
  failure. The client re-handshakes instead of retransmitting a
  state-changing request.

## Protected application messages (`0x01`)

The body is the raw ciphertext produced by Protocomm Security 2: AES-256-GCM
with a 12-byte IV, a 16-byte tag, per-operation counter starting at 1, and no
additional data. The plaintext is a Device Link `Envelope` (`Request`). The
device answers with the encrypted `Envelope` (`Response`) carrying type
`0x01` on the matching TX characteristic:

- session requests are answered on `session_tx` with type `0x01`;
- control requests are answered on `control_tx` with type `0x01`.

Admission:

- `session_rx` accepts both types; its admission is `encrypted_sc_bond`.
- `control_rx` accepts only type `0x01`; its admission is `authorized`.
- A protected body with no `AUTHENTICATED` session is rejected and closes
  the session.
- Ciphertext shorter than the 16-byte tag, a failed tag check, or an invalid
  counter value is malformed: the session is closed, the request is never
  dispatched, and no response is sent.

## Session lifecycle

The Security 2 session is per connection generation and is shared by the
session and control channels. The session has two distinct states:

- `HANDSHAKING`: a handshake command was accepted and the session instance
  exists, but the SRP proof has not yet been verified. Only further
  handshake commands are admitted in this state.
- `AUTHENTICATED`: the SRP proof succeeded (bootstrap POP or long-term
  application credential) and the session key material is established.
  Protected application messages are admitted only in this state.

- Enters `HANDSHAKING` on the first accepted handshake command of the
  generation.
- Enters `AUTHENTICATED` only when the handshake proof verifies. A failed
  proof rejects the handshake: the session instance does not exist and the
  session is `CLOSED`. The client may start a fresh handshake; repeated
  failures must not accumulate session state.
- Closes on: disconnect, connection-generation change, reassembly idle
  (5000 ms), indication confirmation timeout (2000 ms), malformed handshake,
  malformed ciphertext, failed authentication (wrong credential), boot id
  mismatch, or explicit protocol closure.
- While a session is closed, protected messages are rejected and the client
  must re-handshake (recovery) or reconnect.
- Handshake, request dispatch, response encryption, and response
  fragmentation are serialized: one Security 2 transaction is in flight per
  generation (the existing one-transaction contract of
  `docs/device-link-framing-v1.md`).
- A handshake arriving while a protected transaction is in flight aborts
  that transaction and replaces the session (`HANDSHAKING` again): the
  outstanding response is discarded, the old counter stream is abandoned,
  and the client must restart the request in the new session. This is the
  deterministic recovery path after an ambiguous failure; the client never
  retransmits a state-changing request in a stale session.

## Verifier selection

The device answers the handshake with the salt and verifier selected by the
current binding state:

- during an open pairing window, for a peer that has no current binding:
  the bootstrap salt and verifier derived from the QR `pop` of that window;
- during a replacement window, for the already-bound peer whose
  authorization record is still valid: the long-term salt and verifier
  stored in that record, until the replacement commit invalidates the old
  authorization;
- after a replacement commit invalidated the old authorization, and for any
  peer without a binding: the replacement window's bootstrap `pop`
  verifier;
- outside a pairing window, when a committed authorization record exists:
  the long-term salt and verifier stored in that record;
- outside a pairing window with no committed record: the handshake is not
  admitted (no verifier exists; an unknown peer cannot open a session).

Replacement ordering is fixed by `docs/device-link-security-v1.md`:
invalidation of the old authorization precedes deletion of the old bond, so
a crash can leave the device unbound but never dual-authorized.

A handshake that fails the SRP proof (wrong `pop` or wrong application
password) is rejected and the session stays closed. The client chooses its
SRP password by context: the QR `pop` for a bootstrap, the stored application
password for a reconnect (`docs/device-link-qr-v1.md`,
`docs/device-link-security-v1.md`).
