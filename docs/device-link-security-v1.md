# Device Link security v1

Device Link uses two security layers:

1. BLE SMP Secure Connections bonding provides link encryption and peer
   identity resolution.
2. Protocomm Security 2 plus local confirmation proves possession and creates
   an application-specific authorization.

The device supports one primary peer identity and one application credential.
SMP is Secure Connections only, uses a 16-byte encryption key, persists at most
one bond, and distributes encryption and identity keys. Local confirmation is
an application authorization step; it does not convert Just Works pairing into
SMP MITM authentication.

## Bond verification

Before opening a session endpoint, firmware verifies all of these facts:

- the current connection is encrypted;
- the bond-store key is indexed by the normalized peer identity address;
- the stored bond has its Secure Connections flag set;
- a 16-byte LTK is present;
- required local and peer identity keys are present.

The authorization record stores the complete identity address type and six
address bytes. It never stores a connection handle, over-the-air RPA, Android
display address, IRK hash, device name, or advertising discriminator as the
primary identity key.

## Pairing window admission

SMP pairing is a separate fact from the Security 2 session. The device admits
SMP pairing of an unknown peer only while a local pairing window is open
(`BINDABLE` set in the advertisement and in `PublicLinkState`).

- Unknown peer, window closed: pairing is not admitted; the device does not
  initiate or accept SMP security, and `BLE_GAP_EVENT_REPEAT_PAIRING`-style
  requests are ignored. The connection may still read `link_state`.
- Unknown peer, window open: pairing is admitted, Secure Connections only,
  with a 16-byte key and one persistent bond (NVS). The freshly generated QR
  discriminator and POP of that window are the discovery and possession
  tokens for the flow.
- Repeat pairing of the already-bonded peer: admitted only while a
  replacement window is open, after the existing authorization record has
  been invalidated. Outside a replacement window it is rejected.
- Replacement ordering: invalidate the old authorization before deleting the
  old bond, so a crash can leave the device unbound but never dual-authorized.
- Orphan cleanup: a bond without an authorization record is deleted; an
  authorization record without its bond is invalidated and requires a new
  locally confirmed binding.

The binding flow after SMP pairing is defined by the session transport
(`docs/device-link-session-transport-v1.md`) and the QR
(`docs/device-link-qr-v1.md`).

## Bootstrap and commit

The QR contains a fresh 128-bit POP with a bounded lifetime. It is used only by
the bootstrap Security 2 session and is never persisted or logged.

After bootstrap authentication, the user confirms on the device. An
`AuthorizePrepare` request then creates a random nonzero transaction ID, a
16-byte credential ID, and a random application password of at least 16 bytes.
The response is protected by the bootstrap Security 2 session.

The client persists the application password before sending `AuthorizeCommit`.
The device commits one record atomically:

```text
schema version
state = COMMITTED
credential ID
SRP salt and verifier
peer identity address type and value
device authorization ID
```

The plaintext application password is never persisted by the device.
`AuthorizeCommit` is idempotent for the active transaction and credential ID.
The committed record is the only state that grants authorization.

## Reconnection

A reconnect becomes ready only after the encrypted connection matches the
stored Secure Connections bond and a new Security 2 handshake succeeds with
the long-term application credential. A bond alone does not authorize control
or transfer access.

Security 2 calls are serialized. Session and protected control responses use
confirmed indications. Timeout, disconnect, malformed ciphertext, or an
ambiguous response closes the Security 2 session. Asynchronous events never use
the Security 2 request/response counter stream.

## Recovery

- Prepare without Commit leaves no persistent authorization. Disconnect or
  reboot clears the prepared credential and removes a provisional orphan bond.
- A lost Commit response is recovered by reconnecting with the prepared
  long-term credential. Successful authentication proves that Commit won.
- A bond without an authorization record is deleted.
- An authorization record without its bond is invalidated.
- Loss of the application credential requires a new locally confirmed binding.
- Replacement invalidates authorization before deleting the old bond, so a
  crash can leave the device unbound but never dual-authorized.
- Factory reset clears authorization, bonds, CCCDs, Wi-Fi profiles, and
  temporary transfers.

## Secrets and residual risk

QR data, POP, application passwords, Security 2 keys, event keys, Wi-Fi
passwords, salts, and verifiers are excluded from logs. The Protocomm component
is compiled at `INFO` or lower to prevent upstream key dumps.

ESP-IDF Security 2 does not guarantee explicit zeroization of every internal
SRP/session allocation. Conformance may record functional cleanup but must keep
strict upstream zeroization as `not passed` unless the dependency changes.
