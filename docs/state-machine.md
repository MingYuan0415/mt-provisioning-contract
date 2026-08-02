# Provisioning behavior

## External states

`UNAVAILABLE` means the manager or radio cannot accept work. `IDLE` means no
connection attempt is active. `SCANNING`, `CONNECTING`, and `OBTAINING_IP` are
active phases. `CONNECTED` requires an IPv4 lease. `RETRY_WAIT` reports that
device policy will retry without exposing its private delay. `SUSPENDED` means
new operations are temporarily rejected.

## Credential replacement

SSID is 1-32 opaque bytes and cannot contain NUL. Open networks require an
empty password. Personal networks require 8-63 non-NUL bytes. Enterprise and
64-character hexadecimal raw PSKs are unsupported in v1.

Candidate credentials are copied, tested, and persisted only after IPv4 is
obtained. Provisioning succeeds only when the candidate is connected and
persisted. Authentication, association, DHCP, radio, or storage failure leaves
the previous saved profile intact. Storage failure may therefore report an
active IPv4 connection with a failed operation and `profile_persisted=false`.

## Management operations

- Disconnect leaves the saved profile intact and enables `manual_hold` for the
  current boot.
- Reconnect clears `manual_hold` and immediately uses the saved profile.
- Forget disconnects and removes the single saved profile.
- Disabling auto-connect is persistent and does not disconnect an existing
  connection.
- Enabling auto-connect is persistent and starts a connection when a saved
  profile exists and the device is idle.
- Cancellation produces a terminal `CANCELED` operation and does not roll back
  an already completed side effect.

The device retains the active operation and latest terminal result so a client
can recover it with `GetSnapshot` or `GetOperation` after notification loss or
BLE reconnection.
