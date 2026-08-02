# Error model

`ResponseCode` describes immediate request admission. `FailureReason` describes
Wi-Fi or operation outcome. ESP-IDF error integers and disconnect reason codes
must never cross the contract boundary.

| Response code | Meaning |
| --- | --- |
| `OK` | Request was read or admitted. |
| `INVALID_ARGUMENT` | Required data or a defined length/range is invalid. |
| `UNSUPPORTED_VERSION` | Request protocol major is not 1. |
| `UNSUPPORTED_OPERATION` | Capability was not advertised. |
| `BUSY` | Another foreground operation owns the manager. |
| `NOT_FOUND` | Operation, scan generation, or saved profile does not exist. |
| `RADIO_UNAVAILABLE` | Wi-Fi cannot currently accept the operation. |
| `UNAUTHENTICATED` | No valid protected session exists. |
| `INTERNAL` | Stable classification is impossible; logs stay device-local. |

Authentication, AP-not-found, association-timeout, DHCP-timeout, link-lost,
radio, storage, cancellation, and internal outcomes map to the corresponding
`FailureReason`. Apps localize those values; devices do not send presentation
text.
