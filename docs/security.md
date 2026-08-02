# Security

## Bootstrap

The request/response channel uses ESP Protocomm Security 2 with SRP-6a,
username `microtech`, AES-GCM, and nonce patch version 1. The password is a
fresh 128-bit random value encoded as 22 unpadded Base64URL characters in the
on-device QR code. It expires with the 10-minute provisioning window.

QR data, proof of possession, Wi-Fi passwords, Security 2 material, and event
keys must never be logged or persisted. Mutable buffers are overwritten on
success, failure, timeout, cancellation, and disconnect.

## Event subscription

`SubscribeEvents` is sent only after Security 2 is established. Its protected
response contains a fresh 32-byte AES event key, four-byte nonce prefix,
nonzero random subscription ID, sequence baseline, and current snapshot.

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

The deterministic vector in `fixtures/crypto/aes-gcm-v1.json` is normative.
