# Device Link QR bootstrap v1

The device displays one UTF-8 JSON object during an open pairing window. The
QR is the optical possession channel for the binding window: it carries the
fresh discovery discriminator (matching the advertisement) and the proof of
possession used by the bootstrap Security 2 handshake.

```json
{"ver":"link-v1","name":"MT","service":"3e203192-b4bb-4e59-a28a-3d1157854ea3","discriminator":"782r","pop":"AAECAwQFBgcICQoLDA0ODw","expires_in_ms":600000}
```

## Fields

| Field | Type | Rule |
|---|---|---|
| `ver` | string | exactly `link-v1` |
| `name` | string | exactly `MT` (display only, matches the advertised short name) |
| `service` | string | the Device Link service UUID from `profiles/device-link-v1.yaml` |
| `discriminator` | string | exactly 4 unpadded Base64URL characters decoding to 3 bytes, little-endian wire order, nonzero; must equal the `discriminator` of the concurrently advertised Service Data |
| `pop` | string | exactly 22 unpadded Base64URL characters decoding to 16 nonzero bytes; fresh per binding window |
| `expires_in_ms` | number | positive integer at most 3600000; informational only, the device window is authoritative |

The root value is an object. All fields are required, field types are exact,
and unknown fields are ignored (same tolerance as the provisioning v1 QR).
Strings must be valid UTF-8. A numeric or boolean value is never coerced to a
string. Base64URL validation rejects padding, whitespace, and characters
outside the URL-safe alphabet before decoding.

## Discriminator wire mapping

The discriminator is the same 24-bit value encoded little-endian in the
advertisement Service Data (`docs/device-link-discovery-v1.md`). The QR
encodes those three bytes with unpadded Base64URL. Example: advertisement
discriminator `0xABCDEF` produces little-endian bytes `EF CD AB`, which
encode as `782r`.

## Lifecycle

- A fresh `pop` and `discriminator` are generated for every binding window,
  including a replacement window for an already bound device.
- The QR exists only while the pairing window is open. The discriminator must
  never be persisted beyond the window, never appear in `link_state`, logs,
  or metrics, and is not a stable tracking identifier.
- The POP is used only by the bootstrap Security 2 session and is never
  persisted or logged. The plaintext POP never outlives the window.
- The QR must not be accepted from application deep links, clipboard history,
  logs, or cloud backup.
- A bound device outside any window does not display a QR and advertises with
  the `BINDABLE` flag clear and a zero discriminator.

## Client validation order

1. Decode and validate the QR JSON strictly (fields, types, Base64URL, value
   ranges) without coercion.
2. Scan by the Device Link service UUID; when the QR is active, match the
   exact decoded discriminator against the advertisement Service Data.
3. Decode the `pop` Base64URL to its 16 raw bytes. The decoded bytes are the
   SRP password input for the bootstrap Security 2 handshake on `session_rx`
   (`docs/device-link-session-transport-v1.md`): the Base64URL form is only a
   display encoding and is never re-encoded or used as text. Binary-safe
   decoding must preserve `0x00` bytes and all 256 byte values.
4. After Security 2, confirm that the device identity facts agree with the
   QR (`Capabilities` and the binding flow); never trust a QR from any other
   channel.
