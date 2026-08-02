# Request and operation rules

## Success responses

| Request | Success body | Creates operation | Required feature |
| --- | --- | --- | --- |
| `GetCapabilities` | `capabilities` | no | none |
| `GetSnapshot` | `snapshot` | no | none |
| `GetOperation` | `operation` | no | none |
| `StartScan` | `operation_accepted` | yes | `FEATURE_WIFI_SCAN` |
| `GetScanResults` | `scan_results` | no | `FEATURE_WIFI_SCAN` |
| `SetCredentials` | `operation_accepted` | yes | none |
| `CancelOperation` | `operation` | no | none |
| `Disconnect` | `operation_accepted` | yes | `FEATURE_SAVED_NETWORK_MANAGEMENT` |
| `ReconnectSaved` | `operation_accepted` | yes | `FEATURE_SAVED_NETWORK_MANAGEMENT` |
| `ForgetSaved` | `operation_accepted` | yes | `FEATURE_SAVED_NETWORK_MANAGEMENT` |
| `SetAutoConnect` | `operation_accepted` | yes | `FEATURE_AUTO_CONNECT_POLICY` |
| `SubscribeEvents` | `event_subscription` | no | `FEATURE_ENCRYPTED_EVENTS` |
| `FinishSession` | none | no | none |

A newly admitted mutation returns a nonzero operation ID with its declared
type, state `PENDING`, and failure `NONE`. The same ID progresses to `RUNNING`
and exactly one of `SUCCEEDED`, `FAILED`, or `CANCELED`. Read requests never
change operation state.

The device retains both the current active operation, when present, and the
most recent terminal operation. `GetOperation` returns either retained record
when its exact nonzero ID matches and otherwise returns `NOT_FOUND`. Background
automatic connection uses ID zero and is not returned by `GetOperation`.

## Admission and recovery

Only one foreground operation can be pending or running. A second mutation
returns `BUSY`; queries, cancel of the active operation, subscription, and
session finish are still accepted. A saved-network request returns `NOT_FOUND`
when no saved profile exists. A request requiring an unadvertised feature
returns `UNSUPPORTED_OPERATION`.

`CancelOperation` for the active ID returns its current status after accepting
the cancellation. If completion won the race, the retained terminal status is
returned unchanged. The retained terminal ID is therefore idempotent; an older
or unknown ID returns `NOT_FOUND`.

After an ambiguous transport failure, clients recover with `GetSnapshot`,
`GetOperation`, or `GetScanResults(0)` instead of repeating a mutation.
