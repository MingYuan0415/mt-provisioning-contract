# Provisioning behavior

## External states

`UNAVAILABLE` means the manager or radio cannot accept work. `IDLE` means no
connection attempt is active. `SCANNING`, `CONNECTING`, and `OBTAINING_IP` are
active phases. `CONNECTED` requires an IPv4 lease. `RETRY_WAIT` reports that
device policy will retry without exposing its private delay. `SUSPENDED` means
new operations are temporarily rejected.

Snapshot invariants:

- State and failure are never `UNSPECIFIED` in a snapshot returned after
  provisioning service initialization.
- `has_ipv4=true` only in `CONNECTED`; `CONNECTED` always has IPv4.
- `saved_profile` means one valid persistent profile exists.
- `auto_connect=true` requires `saved_profile=true`; with no saved profile the
  auto-connect field is false.
- `profile_persisted` means the current link or target is that saved profile;
  it cannot be true when `saved_profile=false`.
- `manual_hold=true` suppresses automatic connection for the current boot but
  does not remove the saved profile or change the persistent auto-connect
  field.
- `WifiSnapshot.ssid` selects the current IPv4 link, then the active connection
  target, then the saved profile, and is empty only when none exists.
- Snapshot failure is the current connectivity failure. Operation failure is
  retained independently in `last_operation`.

`SCANNING`, `CONNECTING`, and `OBTAINING_IP` carry failure `NONE`.
`CONNECTED` carries `NONE`, except that a candidate which obtained IPv4 but
could not replace the saved record carries `STORAGE`, with
`profile_persisted=false`. Authentication, AP, association, DHCP, and link-loss
failures have no IPv4 and appear in `IDLE` or `RETRY_WAIT`; authentication is
never retried automatically. `UNAVAILABLE` carries `RADIO_UNAVAILABLE` or
`INTERNAL`. `SUSPENDED` may preserve the failure that preceded suspension.
`CANCELED` is an operation outcome; a user-canceled action leaves snapshot
failure as `NONE`.

An `OperationStatus` with state `PENDING`, `RUNNING`, or `SUCCEEDED` carries
failure `NONE`. State `CANCELED` carries failure `CANCELED`. State `FAILED`
carries a specific non-`NONE`, non-`CANCELED` reason. Retained foreground
operations always have a nonzero ID.

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

Every admitted foreground operation has a nonzero ID and exactly one terminal
state. A cancel request does not allocate another ID. Canceling an active ID is
asynchronous; canceling the retained terminal ID returns that terminal state
without another side effect; any other ID returns `NOT_FOUND`.

## Scan results

The device retains only the latest completed scan. It removes empty SSIDs,
groups records by opaque SSID bytes and security, and keeps the strongest RSSI
record in each group. Results are ordered by descending RSSI, then ascending
SSID bytes and security value. At most five records are returned and
`truncated=true` when another distinct normalized record was omitted.

The completed result is stored before the scan operation becomes terminal.
Generation zero requests that result; its exact nonzero generation also works,
while an older or unavailable generation returns `NOT_FOUND`. Hidden-network
support means credentials may name an SSID absent from scan results; hidden
SSIDs are not emitted by a scan.
