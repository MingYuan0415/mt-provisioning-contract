import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_fixtures import ContractValidationError
from scripts.validate_fixtures import DescriptorRegistry
from scripts.validate_fixtures import build_descriptor_set
from scripts.validate_fixtures import load_json
from scripts.validate_fixtures import normalize_scan_records
from scripts.validate_fixtures import require
from scripts.validate_fixtures import validate_compatibility
from scripts.validate_fixtures import validate_proto_version_payload
from scripts.validate_fixtures import validate_qr_payload
from scripts.validate_fixtures import validate_stress_session_payload

from scripts.validate_device_link import validate_link_advertising
from scripts.validate_device_link import validate_link_limits
from scripts.validate_device_link import validate_link_public_state
from scripts.validate_device_link import validate_link_qr_payload
from scripts.validate_device_link import validate_link_session_transport


VALID_QR = {
    "ver": "v1",
    "name": "MT-A1B2C3",
    "transport": "ble",
    "security": 2,
    "username": "microtech",
    "pop": "AAECAwQFBgcICQoLDA0ODw",
    "service": "d8f1c836-b47e-409f-8c21-73979e390e6b",
    "device_id": "A1B2C3",
}

VALID_LINK_QR = {
    "ver": "link-v1",
    "name": "MT",
    "service": "3e203192-b4bb-4e59-a28a-3d1157854ea3",
    "discriminator": "782r",
    "pop": "AAECAwQFBgcICQoLDA0ODw",
    "expires_in_ms": 600000,
}


class ValidatorUnitTest(unittest.TestCase):
    @staticmethod
    def _stress_session() -> dict:
        return {
            "schema": 1,
            "transport": "ble",
            "security": 2,
            "bootstrap_requests": ["get_capabilities"],
            "steady_request": "get_snapshot",
            "interval_ms": 2000,
            "maximum_idle_ms": 10000,
            "maximum_in_flight": 1,
            "request_id": {
                "nonzero": True,
                "unique_per_session": True,
                "retry_reuses_id": False,
            },
            "forbidden_steady_requests": [
                "get_capabilities",
                "get_operation",
                "start_scan",
                "get_scan_results",
                "set_credentials",
                "cancel_operation",
                "disconnect",
                "reconnect_saved",
                "forget_saved",
                "set_auto_connect",
                "subscribe_events",
                "finish_session",
            ],
            "steady_disconnects": 0,
            "steady_reconnects": 0,
            "blind_retry": False,
        }

    def test_require_raises_stable_error(self) -> None:
        with self.assertRaisesRegex(ContractValidationError, "^expected failure$"):
            require(False, "expected failure")

    def test_qr_rejects_boolean_security(self) -> None:
        candidate = dict(VALID_QR)
        candidate["security"] = True
        with self.assertRaisesRegex(ContractValidationError,
                                    "QR security must be int"):
            validate_qr_payload(candidate)

    def test_qr_rejects_non_base64url_pop(self) -> None:
        candidate = dict(VALID_QR)
        candidate["pop"] = "AAECAwQFBgcICQoLDA0OD!"
        with self.assertRaisesRegex(ContractValidationError,
                                    "22 unpadded Base64URL"):
            validate_qr_payload(candidate)

    def test_proto_version_rejects_event_advertisement_mismatch(self) -> None:
        payload = {
            "prov": {
                "ver": "v1.0",
                "sec_ver": 2,
                "sec_patch_ver": 1,
                "cap": ["mt-prov-v1", "mt-events-v1"],
            }
        }
        with self.assertRaisesRegex(ContractValidationError,
                                    "advertisement is inconsistent"):
            validate_proto_version_payload(
                payload,
                ["FEATURE_ENCRYPTED_EVENTS"],
                False,
            )

    def test_scan_normalizes_and_truncates(self) -> None:
        records = [
            {"ssid_hex": "", "security": "OPEN", "rssi": -10,
             "channel": 1, "saved": False},
            {"ssid_hex": "42", "security": "OPEN", "rssi": -50,
             "channel": 6, "saved": False},
            {"ssid_hex": "41", "security": "PERSONAL", "rssi": -30,
             "channel": 11, "saved": True},
            {"ssid_hex": "42", "security": "OPEN", "rssi": -20,
             "channel": 1, "saved": False},
        ]
        normalized, truncated = normalize_scan_records(records, 1)
        self.assertEqual(normalized, [{
            "ssid_hex": "42",
            "security": "OPEN",
            "rssi": -20,
            "channel": 1,
            "saved": False,
        }])
        self.assertTrue(truncated)

    def test_stress_session_rejects_parallel_requests(self) -> None:
        candidate = self._stress_session()
        candidate["maximum_in_flight"] = 2
        with self.assertRaisesRegex(ContractValidationError,
                                    "stress requests must be serial"):
            validate_stress_session_payload(candidate)

    def test_stress_session_rejects_finish_session(self) -> None:
        candidate = self._stress_session()
        candidate["forbidden_steady_requests"].remove("finish_session")
        with self.assertRaisesRegex(ContractValidationError,
                                    "forbidden request list mismatch"):
            validate_stress_session_payload(candidate)

    def test_stress_session_rejects_integer_request_id_flags(self) -> None:
        candidate = self._stress_session()
        candidate["request_id"]["nonzero"] = 1
        with self.assertRaisesRegex(
                ContractValidationError,
                "stress request_id.nonzero must be bool"):
            validate_stress_session_payload(candidate)

    def test_compatibility_rejects_unpinned_verified_entry(self) -> None:
        manifest = """\
schema: 1
combinations:
  - id: invalid-verified
    status: verified
    contract:
      version: 0.1.1
      commit: pending
    android:
      repository: MingYuan0415/mt-android-app
      commit: pending
    device:
      repository: MingYuan0415/mt-device
      commit: pending
    verified_at: 2026-08-02T00:00:00Z
    notes:
      - This entry must be rejected.
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compatibility = root / "compatibility"
            compatibility.mkdir()
            (compatibility / "known-good.yaml").write_text(
                manifest,
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ContractValidationError,
                                        "verified commits must be full SHAs"):
                validate_compatibility(root, "0.1.1")

    def test_link_advertising_rejects_oversize_mutation(self) -> None:
        root = Path(__file__).resolve().parents[1]
        fixture = load_json(root, "fixtures/discovery/advertising-v1.json")
        fixture["max_payload_bytes"] = 29
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "fixtures" / "discovery"
            target.mkdir(parents=True)
            (target / "advertising-v1.json").write_text(
                json.dumps(fixture), encoding="utf-8")
            profiles = Path(directory) / "profiles"
            profiles.mkdir()
            (profiles / "device-link-v1.yaml").write_text(
                (root / "profiles" / "device-link-v1.yaml").read_text(
                    encoding="utf-8"),
                encoding="utf-8")
            with self.assertRaisesRegex(ContractValidationError,
                                        "advertising payload limit mismatch"):
                validate_link_advertising(Path(directory))

    def test_link_limits_rejects_timeout_mutation(self) -> None:
        root = Path(__file__).resolve().parents[1]
        fixture = load_json(root, "fixtures/link-limits-v1.json")
        fixture["reassembly_idle_timeout_ms"] = 5001
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "fixtures"
            target.mkdir(parents=True)
            (target / "link-limits-v1.json").write_text(
                json.dumps(fixture), encoding="utf-8")
            with self.assertRaisesRegex(ContractValidationError,
                                        "reassembly timeout mismatch"):
                validate_link_limits(Path(directory))

    def test_link_public_state_domain_assertions(self) -> None:
        root = Path(__file__).resolve().parents[1]
        registry = DescriptorRegistry(build_descriptor_set(root))
        validate_link_public_state(root, registry)
        limits = load_json(root, "fixtures/link-limits-v1.json")
        message = registry.message_class(
            "microtech.link.v1.PublicLinkState")()
        message.protocol_major = limits["public_link_state_max_version"] + 1
        message.boot_id = 1
        from scripts.validate_device_link import _public_state_domain_valid
        self.assertFalse(_public_state_domain_valid(
            message, limits["public_link_state_max_version"]))
        message.protocol_major = 1
        message.boot_id = 0
        self.assertFalse(_public_state_domain_valid(
            message, limits["public_link_state_max_version"]))

    def test_link_qr_accepts_valid_and_unknown_fields(self) -> None:
        discriminator = validate_link_qr_payload(VALID_LINK_QR)
        self.assertEqual(int.from_bytes(discriminator, "little"), 11259375)
        with_unknown = dict(VALID_LINK_QR)
        with_unknown["future"] = {"ignored": True}
        validate_link_qr_payload(with_unknown)

    def test_link_qr_rejects_boolean_expires(self) -> None:
        candidate = dict(VALID_LINK_QR)
        candidate["expires_in_ms"] = True
        with self.assertRaisesRegex(ContractValidationError,
                                    "expires_in_ms"):
            validate_link_qr_payload(candidate)

    def test_link_qr_rejects_zero_expiry(self) -> None:
        candidate = dict(VALID_LINK_QR)
        candidate["expires_in_ms"] = 0
        with self.assertRaisesRegex(ContractValidationError,
                                    "out of range"):
            validate_link_qr_payload(candidate)

    def test_link_qr_rejects_oversized_expiry(self) -> None:
        candidate = dict(VALID_LINK_QR)
        candidate["expires_in_ms"] = 3600001
        with self.assertRaisesRegex(ContractValidationError,
                                    "out of range"):
            validate_link_qr_payload(candidate)

    def test_link_qr_rejects_zero_discriminator(self) -> None:
        candidate = dict(VALID_LINK_QR)
        candidate["discriminator"] = "AAAA"
        with self.assertRaisesRegex(ContractValidationError,
                                    "must be nonzero"):
            validate_link_qr_payload(candidate)

    def test_link_qr_rejects_padded_discriminator(self) -> None:
        candidate = dict(VALID_LINK_QR)
        candidate["discriminator"] = "782r=="
        with self.assertRaisesRegex(ContractValidationError,
                                    "strict Base64URL"):
            validate_link_qr_payload(candidate)

    def test_link_qr_rejects_short_pop(self) -> None:
        candidate = dict(VALID_LINK_QR)
        candidate["pop"] = "AAECAwQFBgcICQoLDA0"
        with self.assertRaisesRegex(ContractValidationError,
                                    "decode to 16 bytes"):
            validate_link_qr_payload(candidate)

    def test_link_session_transport_semantic_coverage(self) -> None:
        root = Path(__file__).resolve().parents[1]
        validate_link_session_transport(root)


if __name__ == "__main__":
    unittest.main()
