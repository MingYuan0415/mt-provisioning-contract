# MicroTech Provisioning Contract

This repository is the platform-neutral source of truth for provisioning
communication between MicroTech firmware and companion applications.

The v1.0 protocol uses Protocol Buffers for business messages, ESP-IDF
Protocomm Security 2 for the authenticated request/response session, and a
capability-gated AES-256-GCM protected BLE notification channel for state
updates. Devices without encrypted events provide the complete workflow through
polling.

## Repository layout

- `proto/`: canonical wire schemas; generated platform code is not committed.
- `docs/`: transport, security, state-machine, error, and compatibility rules.
- `fixtures/`: cross-platform QR, protobuf, semantic, and cryptographic vectors.
- `compatibility/`: device/app/contract combinations proven on real hardware.
- `scripts/`: contract-only validation tooling used by CI.
- `tests/`: tests for the validator and normalization reference logic.

## Validate

```sh
buf format --diff --exit-code
buf lint
python -m pip install -r requirements.txt
python scripts/validate_fixtures.py
python -m unittest discover -s tests -v
python -O scripts/validate_fixtures.py
```

For a pull request, also run:

```sh
buf breaking --against '.git#branch=main'
```

The v1.0 wire and behavior contract is stable, but a `0.x` repository release
is not evidence of device interoperability. Only combinations marked
`verified` in `compatibility/known-good.yaml` carry that meaning.

## Consumers

Consumers pin this repository as a Git submodule. Firmware and applications
own their code-generation tools and generated sources; this repository owns
only the shared wire and behavior contract.

See `docs/conformance.md` for the consumer acceptance requirements.
The development-only sustained Security 2 workload is defined in
[`docs/stress-session.md`](docs/stress-session.md).

## License

MIT. ESP Protocomm Security 2 remains governed by Espressif's upstream license.
