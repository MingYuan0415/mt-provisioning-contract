# Security

## Bootstrap

The request/response channel uses ESP Protocomm Security 2 with SRP-6a,
username `microtech`, AES-GCM, and nonce patch version 1. The password is a
fresh 128-bit random value encoded as 22 unpadded Base64URL characters in the
on-device QR code. It expires with the 10-minute provisioning window.

BLE pairing, bonding, and link-layer encryption are not required. Security 2
is the application authentication and confidentiality boundary. The device
admits one BLE client during a provisioning window and rejects or disconnects
additional clients.

QR data, proof of possession, Security 2 material, salt, verifier, and event
keys must never be logged or persisted. Wi-Fi passwords must never be logged;
the connectivity manager's single saved Wi-Fi profile is their only permitted
persistent copy. Provisioning adds no second credential store.

The transport clears its request copy after credentials are handed to the
active operation. That operation may retain a candidate in mutable RAM across
a transient BLE disconnect so connection can finish. Candidate and other
transient credential copies are overwritten on success, failure, timeout, or
cancellation. A BLE disconnect, session finish, or window timeout immediately
overwrites Security 2 and event-subscription material.

## Event subscription

Encrypted events are optional. Support exists only when
`FEATURE_ENCRYPTED_EVENTS`, `mt-events-v1`, and the event characteristic are
all present. Otherwise `SubscribeEvents` returns `UNSUPPORTED_OPERATION`.

`SubscribeEvents` is sent only after Security 2 is established. When the
negotiated MTU is at least 185 and the event CCCD is enabled, its protected
response sets `notifications_enabled=true` and contains a fresh 32-byte AES
event key, four-byte nonce prefix, nonzero random subscription ID, sequence
baseline, and current snapshot. With a smaller MTU or disabled CCCD it returns
`OK`, `notifications_enabled=false`, empty key and prefix, zero identifiers,
and the current snapshot. The client then uses polling.

The event notification is a serialized `EncryptedEventFrame`. Encrypt the
serialized `ProvisioningEvent` using AES-256-GCM with a 16-byte tag:

```text
nonce = nonce_prefix || uint64_be(sequence)
aad   = ASCII("MT-PROV-EVENT-V1") || service_uuid_bytes
        || uint32_be(subscription_id) || uint64_be(sequence)
```

The service UUID bytes are the 16 canonical RFC 4122 bytes in display order.
Sequences begin at `sequence_baseline + 1`, strictly increase, and never wrap
within a subscription. A new key, prefix, subscription ID, and sequence space
are created after every Security 2 handshake.

The app rejects an unknown subscription, sequence at or below the accepted
value, invalid length, or invalid GCM tag. A forward sequence gap is not
replayed: the app accepts the authenticated event, marks state uncertain, and
immediately obtains `GetSnapshot`. Disconnect and `FinishSession` invalidate
all subscription material.

Subscription setup, notification loss, or a forward sequence gap never blocks
the polling workflow. Clients poll every 500 ms while an operation is active,
perform a final snapshot read at terminal state, and fetch scan generation zero
when scan results are needed.

The deterministic and tamper vectors in `fixtures/crypto/` are normative.
