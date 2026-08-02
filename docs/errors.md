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

For an `OK` response, the top-level failure is always `NONE`. A
`RADIO_UNAVAILABLE` response also carries `RADIO_UNAVAILABLE`; every other
admission error carries `NONE`. An asynchronous failure appears in the
returned `OperationStatus`, not in a later response envelope.

Request validation order is decrypt and parse, nonzero request ID, protocol
major, recognized body, advertised capability, argument validation, and
foreground admission. A frame that cannot be decrypted or parsed is rejected
by the transport and may produce no `ProvisioningResponse`. Once a request ID
is available, all application-level errors echo it and use no response body.

See `operations.md` for the success body and admission rule of every request.
