# BLE transport

## Discovery

The provisioning service UUID is
`d8f1c836-b47e-409f-8c21-73979e390e6b`. The advertised name is `MT-`
followed by the six uppercase hexadecimal characters in the QR `device_id`.
An app must filter by both the service UUID and the exact QR device name.

The service exposes these characteristics when their capability is enabled.
Properties in this table are minimum requirements; a device may expose
additional read, write, or notify properties, and clients must not depend on
the extras.

| Endpoint | Short UUID | Full UUID | Minimum properties |
| --- | --- | --- | --- |
| `proto-ver` | `0xFF50` | `d8f1ff50-b47e-409f-8c21-73979e390e6b` | read/write |
| `prov-session` | `0xFF51` | `d8f1ff51-b47e-409f-8c21-73979e390e6b` | read/write |
| `mt-prov` | `0xFF52` | `d8f1ff52-b47e-409f-8c21-73979e390e6b` | read/write |
| `mt-events` | `0xFF53` | `d8f1ff53-b47e-409f-8c21-73979e390e6b` | notify + CCCD, when advertised |

`proto-ver` is an unencrypted UTF-8 JSON response using the ESP provisioning
shape. Its required semantic value without events is:

```json
{"prov":{"ver":"v1.0","sec_ver":2,"sec_patch_ver":1,"cap":["mt-prov-v1"]}}
```

An event-capable device adds `mt-events-v1` to `cap`. JSON object ordering and
whitespace are not significant, capability strings are unique, and clients
ignore unknown fields and capability strings. `prov-session` is the unmodified
ESP Protocomm Security 2 handshake endpoint. Every `mt-prov` payload after the
handshake is encrypted by Security 2 patch version 1.

## Requests

The client serializes one GATT operation at a time. It writes an encrypted
`ProvisioningRequest` to `mt-prov`, waits for the write callback, reads the same
characteristic, decrypts the value, and parses `ProvisioningResponse`.

`request_id` must be nonzero and is only correlation, not an idempotency key.
After an ambiguous transport failure the client reads `GetSnapshot` or
`GetOperation`; it must not blindly repeat a mutating request. A device accepts
one foreground operation at a time and returns `BUSY` for another.

Read requests, cancel of the active operation, event subscription, and
`FinishSession` remain admissible while a foreground operation is active. See
`operations.md` for the complete request/response matrix.

## Timing and lifecycle

- QR provisioning mode lasts 10 minutes and admits one BLE client.
- The app requests ATT MTU 517; the ESP transport may negotiate up to 500.
- Encrypted notifications are optional and require MTU 185 or greater plus an
  enabled CCCD. Otherwise the app polls `GetSnapshot` every 500 ms while an
  operation is active and performs one final snapshot read after the operation
  reaches a terminal state.
- A credential or management operation continues across a transient BLE
  disconnect. Re-authentication followed by `GetSnapshot` recovers its state.
- `FinishSession` returns its response before clearing secrets and closing the
  provisioning transport.
- After successful persisted provisioning, the device closes after 30 seconds
  if the app does not call `FinishSession`.

The maximum serialized encrypted event frame is 160 bytes. Scan records are
never included in an event; `ScanChanged` directs the client to fetch them.

`GetScanResults.generation=0` requests the most recently completed scan. A
nonzero generation requests that exact retained result and returns `NOT_FOUND`
when it is no longer available. This lets polling clients recover scan results
without relying on an event notification for the new generation number.
