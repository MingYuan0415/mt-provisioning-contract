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

The QR contains a fresh 128-bit POP with a bounded lifetime. The client
decodes the Base64URL `pop` to its 16 raw bytes and uses exactly those bytes as
the bootstrap SRP password (`docs/device-link-qr-v1.md`). The POP is used only
by the bootstrap Security 2 session and is never persisted or logged.

The binding flow order is fixed: `AuthorizePrepare` first, then local
confirmation, then `AuthorizeCommit`.

1. After bootstrap authentication the client sends `AuthorizePrepare` on the
   session channel. The device creates a random nonzero transaction ID, a
   16-byte credential ID, and a random application password of at least 16
   bytes. The response is protected by the bootstrap Security 2 session.
   Repeating `AuthorizePrepare` with a fresh request ID while the same
   transaction is active returns the same transaction ID, credential ID, and
   application password; the transaction expires after `expires_in_ms`.
2. The user confirms the binding on the device. Until the local confirmation
   is granted, `AuthorizeCommit` fails with `LINK_ERROR_CONFIRMATION_REQUIRED`.
3. The client persists the application password before sending
   `AuthorizeCommit`. The device commits one record atomically:

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

A binding that never commits leaves no persistent authorization. A provisional
bond created during the window is deleted on local deny, prepare expiry, window
close or timeout, disconnect, protocol failure, or a failed commit; a bond
whose commit succeeded is promoted and survives.

## Recovery

- Prepare without Commit leaves no persistent authorization. Disconnect or
  reboot clears the prepared credential and removes a provisional orphan bond.
- A lost Commit response is recovered by reconnecting with the prepared
  long-term credential. Successful authentication proves that Commit won; the
  client then sends `GetAuthorization` with the prepared credential ID under
  the `RECOVERY_QUERY` envelope flag. The device returns the committed
  `AuthorizationResult` (including the opaque `device_authorization_id`) only
  when the session was authenticated with the long-term credential of that
  record and the peer identity matches the record. The client must compare the
  returned credential ID with the prepared one; a mismatch means the prepare
  was replaced and the client must not retry the old Commit.
- `GetCapabilities` and `GetLinkSnapshot` are admitted on the session channel
  after bootstrap or long-term authentication, before authorization.
- A bond without an authorization record is deleted.
- An authorization record without its bond is invalidated.
- Loss of the application credential requires a new locally confirmed binding.
- Replacement invalidates authorization before deleting the old bond, so a
  crash can leave the device unbound but never dual-authorized.
- Local revoke and factory reset are device-local operations with no v1 wire
  command. Both are journaled before any mutation; a crash mid-operation
  resumes the journaled intent at startup before advertising or network
  autoconnect, so a crash never leaves a half-cleared or dual-authorized
  state. Factory reset clears authorization, bonds, CCCDs, Wi-Fi profiles, and
  temporary transfers.

## Reconnection

A reconnect becomes ready only after the encrypted connection matches the
stored Secure Connections bond and a new Security 2 handshake succeeds with
the long-term application credential. A bond alone does not authorize control
or transfer access.

Security 2 calls are serialized. Session and protected control responses use
confirmed indications, one fragment at a time: the next fragment of a response
is sent only after the previous indication was confirmed, so responses stream
at any negotiated MTU down to 23. Timeout, disconnect, malformed ciphertext, or
an ambiguous response closes the Security 2 session. Asynchronous events never
use the Security 2 request/response counter stream.

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
