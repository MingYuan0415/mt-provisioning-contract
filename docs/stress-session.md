# Security 2 stress session

This development-only workload keeps one real Protocomm Security 2 session
active while firmware exercises Wi-Fi, audio, display, and application
lifecycle paths. It does not add a BLE endpoint, protobuf message, capability,
or production behavior.

## Bootstrap

The application scans the displayed QR payload, connects to the advertised BLE
service, and completes the existing Security 2 handshake. Capability discovery
may run before the measured interval. The measured interval starts only after a
protected `GetSnapshot` request succeeds.

## Measured interval

- Send one protected `GetSnapshot` every 2 seconds.
- Use a nonzero request ID that has not appeared earlier in the session.
- Keep at most one GATT request in flight and wait for its response before
  sending another request.
- Do not send mutations, subscriptions, cancellation, or `FinishSession`.
- Do not blindly retry a failed request. Report the failure and use a fresh
  request ID only when the test controller explicitly continues the campaign.
- Keep the BLE connection and Security 2 session open. A disconnect or reconnect
  fails the measured interval.

The device must observe a successful protected request at least every 10
seconds. The normal 2-second cadence remains the throughput target; 10 seconds
is only the maximum scheduling gap accepted by the firmware campaign.

## Completion

The application leaves the session open until the firmware enters cleanup and
closes provisioning. It must not send `FinishSession`. A transport close after
the firmware cleanup marker is expected and is outside the measured interval.

The machine-readable requirements are in
[`fixtures/stress-session-v1.json`](../fixtures/stress-session-v1.json).
