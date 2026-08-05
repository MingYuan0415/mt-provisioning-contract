# Device Link advertising and discovery v1

This document freezes the wire contract an Android scanner relies on. The
advertising interval and fast/slow timing are runtime policy, calibrated on
hardware, and are not part of the wire contract.

## Payload

A Device Link v1 advertisement is a legacy connectable undirected
advertisement. All three AD structures below are in the primary advertising
packet; nothing relies on a scan response.

| AD type | Content | Size |
| --- | --- | --- |
| Flags (0x01) | `LE General Discoverable | BR/EDR Not Supported` | 3 |
| Service Data (0x21) | Device Link 128-bit service UUID, adv version, flags, discriminator | 23 |
| Short Local Name (0x08) | `MT` | 4 |

Service Data layout:

```text
service_uuid[16]  little-endian, fixed by profiles/device-link-v1.yaml
adv_version:u8    = 1
flags:u8          bit 0 BINDABLE, bits 1-7 reserved and zero
discriminator:u24 little-endian, fresh per binding window
```

## Discriminator

The 24-bit discriminator is freshly generated for every binding window and is
matched to the on-screen QR. It is a discovery token only:

- it must never be persisted beyond the window;
- it must never appear in link_state, logs, or metrics;
- it is not a stable tracking identifier;
- advertising carries a discriminator only while `BINDABLE` is set; otherwise
  the three-byte slot is encoded as zero.

`BINDABLE` is set while the device is in a pairing window, including a
replacement window for an already bound device (`state_flags` value 3). A
bound device outside any window advertises with the flag clear and a zero
discriminator.

## Scanning rules

Android filters by the service UUID first, then by the exact discriminator from
the QR when a window is active. The short name `MT` is display-only and is not
used for identity matching. Advertising content never includes Wi-Fi names,
credentials, authorization state, or stable device IDs.
