# QR bootstrap

The device displays one UTF-8 JSON object:

```json
{"ver":"v1","name":"MT-A1B2C3","transport":"ble","security":2,"username":"microtech","pop":"AAECAwQFBgcICQoLDA0ODw","service":"d8f1c836-b47e-409f-8c21-73979e390e6b","device_id":"A1B2C3"}
```

The root value is an object. All fields are required, field types are exact,
and unknown fields are ignored. Validation rules:

- `ver`, `transport`, `security`, `username`, and `service` must exactly match
  the v1 constants.
- `device_id` is exactly six uppercase hexadecimal characters.
- `name` is exactly `MT-` plus `device_id`.
- `pop` is exactly 22 unpadded Base64URL characters decoding to 16 bytes.
- After Security 2, `Capabilities.device_id` must equal the QR device ID.

Strings must be valid UTF-8. A numeric or boolean value is never coerced to a
string, and `security` must be the JSON number 2 rather than a numeric string.
Base64URL validation rejects padding, whitespace, and characters outside the
URL-safe alphabet before decoding.

The QR is an optical possession channel. It contains no Wi-Fi information and
must not be accepted from application deep links, clipboard history, logs, or
cloud backup.
