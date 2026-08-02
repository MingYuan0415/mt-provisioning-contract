# BLE transport

## Discovery

The provisioning service UUID is
`d8f1c836-b47e-409f-8c21-73979e390e6b`. The advertised name is `MT-`
followed by the six uppercase hexadecimal characters in the QR `device_id`.
An app must filter by both the service UUID and the exact QR device name.

The service exposes these characteristics:

| Endpoint | Short UUID | Full UUID | Properties |
| --- | --- | --- | --- |
| `proto-ver` | `0xFF50` | `d8f1ff50-b47e-409f-8c21-73979e390e6b` | read/write |
| `prov-session` | `0xFF51` | `d8f1ff51-b47e-409f-8c21-73979e390e6b` | read/write |
| `mt-prov` | `0xFF52` | `d8f1ff52-b47e-409f-8c21-73979e390e6b` | read/write |
| `mt-events` | `0xFF53` | `d8f1ff53-b47e-409f-8c21-73979e390e6b` | notify + CCCD |

`proto-ver` follows the ESP provisioning version response shape and advertises
`sec2`, `mt-prov-v1`, and `mt-events-v1`. `prov-session` is the unmodified ESP
Protocomm Security 2 handshake endpoint. Every `mt-prov` payload after the
handshake is encrypted by Security 2 patch version 1.

## Requests

The client serializes one GATT operation at a time. It writes an encrypted
`ProvisioningRequest` to `mt-prov`, waits for the write callback, reads the same
characteristic, decrypts the value, and parses `ProvisioningResponse`.

`request_id` must be nonzero and is only correlation, not an idempotency key.
After an ambiguous transport failure the client reads `GetSnapshot` or
`GetOperation`; it must not blindly repeat a mutating request. A device accepts
one foreground operation at a time and returns `BUSY` for another.

## Timing and lifecycle

- QR provisioning mode lasts 10 minutes and admits one BLE client.
- The app requests ATT MTU 517; the ESP transport may negotiate up to 500.
- Encrypted notifications require MTU 185 or greater. Otherwise the app polls
  `GetSnapshot` every 500 ms while an operation is active and performs one
  final snapshot read after the operation reaches a terminal state.
- A credential or management operation continues across a transient BLE
  disconnect. Re-authentication followed by `GetSnapshot` recovers its state.
- `FinishSession` clears session secrets and closes provisioning transport.
- After successful persisted provisioning, the device closes after 30 seconds
  if the app does not call `FinishSession`.

The maximum serialized encrypted event frame is 160 bytes. Scan records are
never included in an event; `ScanChanged` directs the client to fetch them.

`GetScanResults.generation=0` requests the most recently completed scan. A
nonzero generation requests that exact retained result and returns `NOT_FOUND`
when it is no longer available. This lets polling clients recover scan results
without relying on an event notification for the new generation number.
