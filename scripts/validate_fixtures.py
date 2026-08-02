from __future__ import annotations

import base64
import json
import re
import struct
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parents[1]
SERVICE_UUID = "d8f1c836-b47e-409f-8c21-73979e390e6b"
QR_FIELDS = {
    "ver",
    "name",
    "transport",
    "security",
    "username",
    "pop",
    "service",
    "device_id",
}


def load_json(relative_path: str):
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def validate_qr_payload(qr: dict) -> None:
    assert QR_FIELDS <= qr.keys()
    assert qr["ver"] == "v1"
    assert qr["transport"] == "ble"
    assert qr["security"] == 2
    assert qr["username"] == "microtech"
    assert qr["service"] == SERVICE_UUID
    assert re.fullmatch(r"[0-9A-F]{6}", qr["device_id"])
    assert qr["name"] == f"MT-{qr['device_id']}"
    assert len(qr["pop"]) == 22 and "=" not in qr["pop"]
    decoded = base64.urlsafe_b64decode(qr["pop"] + "==")
    assert len(decoded) == 16


def validate_qr() -> None:
    qr = load_json("fixtures/qr/valid-v1.json")
    validate_qr_payload(qr)

    invalid = load_json("fixtures/qr/invalid-v1.json")
    assert len({case["id"] for case in invalid}) == len(invalid)
    for case in invalid:
        candidate = qr | case["replace"]
        try:
            validate_qr_payload(candidate)
        except (AssertionError, ValueError):
            continue
        raise AssertionError(f"invalid QR fixture passed validation: {case['id']}")


def validate_crypto() -> None:
    vector = load_json("fixtures/crypto/aes-gcm-v1.json")
    key = bytes.fromhex(vector["key_hex"])
    prefix = bytes.fromhex(vector["nonce_prefix_hex"])
    sequence = vector["sequence"]
    subscription_id = vector["subscription_id"]
    nonce = prefix + struct.pack(">Q", sequence)
    aad = (
        b"MT-PROV-EVENT-V1"
        + uuid.UUID(vector["service_uuid"]).bytes
        + struct.pack(">IQ", subscription_id, sequence)
    )
    assert nonce.hex() == vector["nonce_hex"]
    assert aad.hex() == vector["aad_hex"]
    encrypted = AESGCM(key).encrypt(
        nonce, bytes.fromhex(vector["plaintext_hex"]), aad
    )
    assert encrypted[:-16].hex() == vector["ciphertext_hex"]
    assert encrypted[-16:].hex() == vector["tag_hex"]


def validate_other_fixtures() -> None:
    golden = load_json("fixtures/protobuf/golden-v1.json")
    assert len({case["id"] for case in golden}) == len(golden)
    for case in golden:
        assert bytes.fromhex(case["hex"])
        assert case["type"].startswith("microtech.provisioning.v1.")

    semantic = load_json("fixtures/semantic-cases.json")
    assert len({case["id"] for case in semantic}) == len(semantic)
    semantic_by_id = {case["id"]: case for case in semantic}
    assert semantic_by_id["scan-latest-generation-zero"] == {
        "id": "scan-latest-generation-zero",
        "requested_generation": 0,
        "result": "LATEST_COMPLETED",
    }
    assert semantic_by_id["poll-terminal-refresh"]["poll_interval_ms"] == 500
    assert semantic_by_id["poll-terminal-refresh"]["final_snapshot_required"]
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.1.0"


def main() -> None:
    validate_qr()
    validate_crypto()
    validate_other_fixtures()
    print("contract fixtures valid")


if __name__ == "__main__":
    main()
