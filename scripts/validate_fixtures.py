from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import struct
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool
from google.protobuf import json_format
from google.protobuf import message_factory
from google.protobuf.message import DecodeError


ROOT = Path(__file__).resolve().parents[1]
SERVICE_UUID = "d8f1c836-b47e-409f-8c21-73979e390e6b"
PROTO_PREFIX = "microtech.provisioning.v1."
EVENT_FEATURE = "FEATURE_ENCRYPTED_EVENTS"
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
QR_STRING_FIELDS = QR_FIELDS - {"security"}
SECURITY_ORDER = {"OPEN": 1, "PERSONAL": 2, "UNSUPPORTED": 3}
REQUEST_VALIDATION_ORDER = [
    "decrypt_and_parse",
    "request_id",
    "protocol_major",
    "recognized_body",
    "advertised_feature",
    "arguments",
    "foreground_admission",
]
SEMANTIC_CASES = {
    "personal-success",
    "open-success",
    "hidden-success",
    "authentication-retains-old",
    "storage-connected-not-persisted",
    "scan-normalized-truncated",
    "scan-latest-generation-zero",
    "scan-unavailable-generation-zero",
    "scan-stored-before-terminal",
    "poll-terminal-refresh",
    "events-unadvertised",
    "events-low-mtu",
    "events-cccd-disabled",
    "events-enabled",
    "disconnect-manual-hold",
    "reconnect-saved",
    "forget-saved",
    "disable-auto-connect-keeps-link",
    "cancel-active",
    "cancel-completion-race",
    "cancel-terminal-idempotent",
    "cancel-unknown",
    "identifier-restart-scope",
    "snapshot-connected",
    "snapshot-unsaved-target",
    "finish-response-before-close",
}
STRESS_FORBIDDEN_REQUESTS = [
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
]


class ContractValidationError(ValueError):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: UniqueKeyLoader, node: yaml.Node,
                              deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ContractValidationError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractValidationError(message)


def require_exact_type(value: Any, expected: type, name: str) -> None:
    require(type(value) is expected, f"{name} must be {expected.__name__}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(root: Path, relative_path: str) -> Any:
    path = root / relative_path
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractValidationError(f"invalid JSON {relative_path}: {error}") from error


def load_yaml(root: Path, relative_path: str) -> Any:
    path = root / relative_path
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ContractValidationError(f"invalid YAML {relative_path}: {error}") from error


def build_descriptor_set(root: Path, descriptor_path: Path | None = None) -> bytes:
    if descriptor_path is not None:
        try:
            return descriptor_path.read_bytes()
        except OSError as error:
            raise ContractValidationError(f"cannot read descriptor set: {error}") from error

    with tempfile.TemporaryDirectory(prefix="mt-provisioning-") as directory:
        output = Path(directory) / "contract.binpb"
        command = [
            "buf",
            "build",
            "--as-file-descriptor-set",
            "-o",
            str(output),
        ]
        try:
            result = subprocess.run(
                command,
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as error:
            raise ContractValidationError(
                "buf is required to build the descriptor set"
            ) from error
        require(result.returncode == 0, f"buf build failed: {result.stderr.strip()}")
        return output.read_bytes()


class DescriptorRegistry:
    def __init__(self, serialized: bytes) -> None:
        descriptor_set = descriptor_pb2.FileDescriptorSet()
        try:
            descriptor_set.ParseFromString(serialized)
        except DecodeError as error:
            raise ContractValidationError("invalid FileDescriptorSet") from error
        require(len(descriptor_set.file) > 0, "descriptor set is empty")

        self.pool = descriptor_pool.DescriptorPool()
        pending = list(descriptor_set.file)
        while pending:
            remaining = []
            progress = False
            for file_descriptor in pending:
                try:
                    self.pool.Add(file_descriptor)
                    progress = True
                except TypeError:
                    remaining.append(file_descriptor)
            require(progress, "descriptor dependencies could not be resolved")
            pending = remaining

    def message_class(self, full_name: str) -> type:
        try:
            descriptor = self.pool.FindMessageTypeByName(full_name)
        except KeyError as error:
            raise ContractValidationError(f"unknown protobuf type: {full_name}") from error
        return message_factory.GetMessageClass(descriptor)


def _protobuf_json(message: Any) -> dict[str, Any]:
    return json_format.MessageToDict(
        message,
        preserving_proto_field_name=True,
    )


def validate_protobuf(root: Path, registry: DescriptorRegistry) -> None:
    golden = load_json(root, "fixtures/protobuf/golden-v1.json")
    require_exact_type(golden, list, "protobuf golden fixture")
    ids = [case.get("id") for case in golden if type(case) is dict]
    require(len(ids) == len(golden), "every protobuf golden case needs an id")
    require(len(set(ids)) == len(ids), "duplicate protobuf golden id")

    parsed_by_id: dict[str, Any] = {}
    for case in golden:
        full_name = case.get("type")
        require(type(full_name) is str and full_name.startswith(PROTO_PREFIX),
                f"invalid protobuf type in {case.get('id')}")
        try:
            payload = bytes.fromhex(case.get("hex", ""))
        except ValueError as error:
            raise ContractValidationError(
                f"invalid protobuf hex in {case.get('id')}"
            ) from error
        require(payload, f"empty protobuf payload in {case.get('id')}")
        message = registry.message_class(full_name)()
        try:
            message.ParseFromString(payload)
        except DecodeError as error:
            raise ContractValidationError(
                f"golden protobuf did not parse: {case.get('id')}"
            ) from error
        require(_protobuf_json(message) == case.get("json"),
                f"decoded protobuf mismatch: {case.get('id')}")
        require(message.SerializeToString(deterministic=True) == payload,
                f"protobuf is not canonical: {case.get('id')}")
        parsed_by_id[case["id"]] = message

    capabilities = parsed_by_id.get("capabilities-v1-no-events")
    require(capabilities is not None, "missing protocol capabilities golden")
    require(capabilities.protocol_version.major == 1 and
            capabilities.protocol_version.minor == 0,
            "capabilities protocol version must be 1.0")
    require(5 not in capabilities.features,
            "no-events capabilities unexpectedly advertise encrypted events")

    invalid = load_json(root, "fixtures/protobuf/invalid-v1.json")
    require_exact_type(invalid, list, "invalid protobuf fixture")
    invalid_ids = [case.get("id") for case in invalid if type(case) is dict]
    require(len(invalid_ids) == len(invalid), "every invalid protobuf case needs an id")
    require(len(set(invalid_ids)) == len(invalid_ids), "duplicate invalid protobuf id")
    for case in invalid:
        message = registry.message_class(case.get("type", ""))()
        try:
            payload = bytes.fromhex(case.get("hex", ""))
            message.ParseFromString(payload)
        except (ValueError, DecodeError):
            continue
        raise ContractValidationError(
            f"invalid protobuf parsed successfully: {case.get('id')}"
        )


def validate_qr_payload(qr: Any) -> None:
    require_exact_type(qr, dict, "QR root")
    require(QR_FIELDS <= qr.keys(), "QR is missing a required field")
    for field in QR_STRING_FIELDS:
        require_exact_type(qr[field], str, f"QR {field}")
    require_exact_type(qr["security"], int, "QR security")
    require(qr["ver"] == "v1", "QR version must be v1")
    require(qr["transport"] == "ble", "QR transport must be ble")
    require(qr["security"] == 2, "QR security must be 2")
    require(qr["username"] == "microtech", "QR username mismatch")
    require(qr["service"] == SERVICE_UUID, "QR service UUID mismatch")
    require(re.fullmatch(r"[0-9A-F]{6}", qr["device_id"]) is not None,
            "QR device_id must be six uppercase hexadecimal characters")
    require(qr["name"] == f"MT-{qr['device_id']}", "QR name mismatch")
    require(re.fullmatch(r"[A-Za-z0-9_-]{22}", qr["pop"]) is not None,
            "QR pop must be 22 unpadded Base64URL characters")
    try:
        decoded = base64.b64decode(
            qr["pop"] + "==",
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise ContractValidationError("QR pop is not strict Base64URL") from error
    require(len(decoded) == 16, "QR pop must decode to 16 bytes")


def validate_qr(root: Path) -> None:
    base = load_json(root, "fixtures/qr/valid-v1.json")
    validate_qr_payload(base)
    with_unknown = dict(base)
    with_unknown["future"] = {"ignored": True}
    validate_qr_payload(with_unknown)

    invalid = load_json(root, "fixtures/qr/invalid-v1.json")
    require_exact_type(invalid, list, "invalid QR fixture")
    ids = [case.get("id") for case in invalid if type(case) is dict]
    require(len(ids) == len(invalid), "every invalid QR case needs an id")
    require(len(set(ids)) == len(ids), "duplicate invalid QR id")
    for case in invalid:
        candidate = case.get("payload", dict(base))
        if type(candidate) is dict:
            candidate = dict(candidate)
            for field in case.get("remove", []):
                candidate.pop(field, None)
            candidate.update(case.get("replace", {}))
        try:
            validate_qr_payload(candidate)
        except ContractValidationError:
            continue
        raise ContractValidationError(f"invalid QR passed: {case.get('id')}")


def validate_proto_version_payload(payload: Any, features: Any,
                                   event_characteristic: Any) -> None:
    require_exact_type(payload, dict, "proto-ver root")
    require_exact_type(features, list, "proto-ver features")
    require(all(type(feature) is str for feature in features),
            "proto-ver features must be strings")
    require(len(set(features)) == len(features),
            "proto-ver features must be unique")
    require_exact_type(event_characteristic, bool,
                       "proto-ver event_characteristic")
    require_exact_type(payload.get("prov"), dict, "proto-ver prov")
    prov = payload["prov"]
    require_exact_type(prov.get("ver"), str, "proto-ver ver")
    require_exact_type(prov.get("sec_ver"), int, "proto-ver sec_ver")
    require_exact_type(prov.get("sec_patch_ver"), int,
                       "proto-ver sec_patch_ver")
    require_exact_type(prov.get("cap"), list, "proto-ver cap")
    require(prov["ver"] == "v1.0", "proto-ver version mismatch")
    require(prov["sec_ver"] == 2, "proto-ver security version mismatch")
    require(prov["sec_patch_ver"] == 1,
            "proto-ver security patch mismatch")
    require(all(type(capability) is str for capability in prov["cap"]),
            "proto-ver capabilities must be strings")
    require(len(set(prov["cap"])) == len(prov["cap"]),
            "proto-ver capabilities must be unique")
    require("mt-prov-v1" in prov["cap"], "proto-ver base capability missing")
    has_event_capability = "mt-events-v1" in prov["cap"]
    has_event_feature = EVENT_FEATURE in features
    require(has_event_capability == has_event_feature == event_characteristic,
            "encrypted event advertisement is inconsistent")


def validate_proto_version(root: Path) -> None:
    valid = load_json(root, "fixtures/version/valid-v1.json")
    require_exact_type(valid, dict, "valid proto-ver fixture")
    require(set(valid) == {"without_events", "with_events"},
            "proto-ver fixture variants mismatch")
    for variant in valid.values():
        validate_proto_version_payload(
            variant.get("payload"),
            variant.get("features"),
            variant.get("event_characteristic"),
        )

    invalid = load_json(root, "fixtures/version/invalid-v1.json")
    require_exact_type(invalid, list, "invalid proto-ver fixture")
    ids = [case.get("id") for case in invalid if type(case) is dict]
    require(len(ids) == len(invalid), "every invalid proto-ver case needs an id")
    require(len(set(ids)) == len(ids), "duplicate invalid proto-ver id")
    for case in invalid:
        try:
            validate_proto_version_payload(
                case.get("payload"),
                case.get("features"),
                case.get("event_characteristic"),
            )
        except ContractValidationError:
            continue
        raise ContractValidationError(
            f"invalid proto-ver passed: {case.get('id')}"
        )


def _event_nonce(prefix: bytes, sequence: int) -> bytes:
    return prefix + struct.pack(">Q", sequence)


def _event_aad(service_uuid: str, subscription_id: int, sequence: int) -> bytes:
    return (
        b"MT-PROV-EVENT-V1"
        + uuid.UUID(service_uuid).bytes
        + struct.pack(">IQ", subscription_id, sequence)
    )


def _flipped(value: bytes) -> bytes:
    require(bool(value), "cannot mutate empty cryptographic value")
    return bytes([value[0] ^ 1]) + value[1:]


def validate_crypto(root: Path) -> None:
    vector = load_json(root, "fixtures/crypto/aes-gcm-v1.json")
    key = bytes.fromhex(vector["key_hex"])
    prefix = bytes.fromhex(vector["nonce_prefix_hex"])
    sequence = vector["sequence"]
    subscription_id = vector["subscription_id"]
    plaintext = bytes.fromhex(vector["plaintext_hex"])
    nonce = _event_nonce(prefix, sequence)
    aad = _event_aad(vector["service_uuid"], subscription_id, sequence)
    require(len(key) == 32, "event key must be 32 bytes")
    require(len(prefix) == 4, "event nonce prefix must be 4 bytes")
    require(nonce.hex() == vector["nonce_hex"], "event nonce vector mismatch")
    require(aad.hex() == vector["aad_hex"], "event AAD vector mismatch")
    encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
    require(encrypted[:-16].hex() == vector["ciphertext_hex"],
            "event ciphertext vector mismatch")
    require(encrypted[-16:].hex() == vector["tag_hex"],
            "event tag vector mismatch")
    require(AESGCM(key).decrypt(nonce, encrypted, aad) == plaintext,
            "event vector did not decrypt")

    invalid = load_json(root, "fixtures/crypto/invalid-v1.json")
    require_exact_type(invalid, list, "invalid crypto fixture")
    mutations = [case.get("mutation") for case in invalid]
    require(len(set(mutations)) == len(invalid), "duplicate crypto mutation")
    for case in invalid:
        test_nonce = nonce
        test_aad = aad
        test_encrypted = encrypted
        mutation = case.get("mutation")
        if mutation == "nonce_prefix":
            test_nonce = _event_nonce(_flipped(prefix), sequence)
        elif mutation == "sequence":
            test_nonce = _event_nonce(prefix, sequence + 1)
            test_aad = _event_aad(vector["service_uuid"], subscription_id,
                                  sequence + 1)
        elif mutation == "subscription_id":
            test_aad = _event_aad(vector["service_uuid"], subscription_id + 1,
                                  sequence)
        elif mutation == "service_uuid":
            test_aad = _event_aad(
                "00000000-0000-0000-0000-000000000000",
                subscription_id,
                sequence,
            )
        elif mutation == "ciphertext":
            test_encrypted = _flipped(encrypted[:-16]) + encrypted[-16:]
        elif mutation == "tag":
            test_encrypted = encrypted[:-16] + _flipped(encrypted[-16:])
        else:
            raise ContractValidationError(f"unknown crypto mutation: {mutation}")
        try:
            AESGCM(key).decrypt(test_nonce, test_encrypted, test_aad)
        except InvalidTag:
            continue
        raise ContractValidationError(
            f"tampered crypto vector decrypted: {case.get('id')}"
        )


def validate_request_matrix(root: Path, registry: DescriptorRegistry) -> None:
    matrix = load_json(root, "fixtures/request-response-v1.json")
    require_exact_type(matrix, dict, "request-response fixture")
    require(matrix.get("validation_order") == REQUEST_VALIDATION_ORDER,
            "request validation order mismatch")
    entries = matrix.get("requests")
    require_exact_type(entries, list, "request-response entries")
    request_descriptor = registry.pool.FindMessageTypeByName(
        PROTO_PREFIX + "ProvisioningRequest"
    )
    response_descriptor = registry.pool.FindMessageTypeByName(
        PROTO_PREFIX + "ProvisioningResponse"
    )
    request_fields = {field.name for field in request_descriptor.oneofs_by_name["body"].fields}
    response_fields = {field.name for field in response_descriptor.oneofs_by_name["body"].fields}
    expected_success_bodies = {
        "get_capabilities": "capabilities",
        "get_snapshot": "snapshot",
        "get_operation": "operation",
        "start_scan": "operation_accepted",
        "get_scan_results": "scan_results",
        "set_credentials": "operation_accepted",
        "cancel_operation": "operation",
        "disconnect": "operation_accepted",
        "reconnect_saved": "operation_accepted",
        "forget_saved": "operation_accepted",
        "set_auto_connect": "operation_accepted",
        "subscribe_events": "event_subscription",
        "finish_session": None,
    }
    fixture_fields = {entry.get("request") for entry in entries}
    require(fixture_fields == request_fields, "request matrix does not cover every request")
    require(len(fixture_fields) == len(entries), "duplicate request matrix entry")
    feature_descriptor = registry.pool.FindEnumTypeByName(PROTO_PREFIX + "Feature")
    feature_names = {value.name for value in feature_descriptor.values}
    for entry in entries:
        success_body = entry.get("success_body")
        require(success_body == expected_success_bodies[entry["request"]],
                f"incorrect success body for {entry.get('request')}")
        require(success_body is None or success_body in response_fields,
                f"invalid success body for {entry.get('request')}")
        require_exact_type(entry.get("creates_operation"), bool,
                           f"creates_operation for {entry.get('request')}")
        feature = entry.get("required_feature")
        require(feature is None or feature in feature_names,
                f"invalid feature for {entry.get('request')}")

    operation_requests = {
        entry["request"] for entry in entries if entry["creates_operation"]
    }
    require(operation_requests == {
        "start_scan",
        "set_credentials",
        "disconnect",
        "reconnect_saved",
        "forget_saved",
        "set_auto_connect",
    }, "operation-creating request set mismatch")
    require(matrix.get("new_operation") == {
        "operation_id": "NONZERO",
        "state": "OPERATION_STATE_PENDING",
        "failure": "FAILURE_REASON_NONE",
    }, "new operation response invariant mismatch")
    require(set(matrix.get("allowed_while_busy", [])) == {
        "get_capabilities",
        "get_snapshot",
        "get_operation",
        "get_scan_results",
        "cancel_operation",
        "subscribe_events",
        "finish_session",
    }, "busy admission set mismatch")
    require(matrix.get("cancel") == {
        "active": "ACCEPT_CURRENT_STATUS",
        "retained_terminal": "RETURN_TERMINAL_STATUS",
        "unknown": "NOT_FOUND",
        "creates_operation": False,
    }, "cancel matrix mismatch")
    require(matrix.get("top_level_failure") == {
        "OK": "FAILURE_REASON_NONE",
        "RADIO_UNAVAILABLE": "FAILURE_REASON_RADIO_UNAVAILABLE",
        "OTHER_ADMISSION_ERROR": "FAILURE_REASON_NONE",
    }, "top-level failure matrix mismatch")


def normalize_scan_records(records: Any, capacity: int) -> tuple[list[dict[str, Any]], bool]:
    require_exact_type(records, list, "scan input")
    require(type(capacity) is int and capacity > 0, "scan capacity must be positive")
    normalized: dict[tuple[bytes, int], dict[str, Any]] = {}
    for index, record in enumerate(records):
        require_exact_type(record, dict, f"scan record {index}")
        try:
            ssid = bytes.fromhex(record.get("ssid_hex", ""))
        except ValueError as error:
            raise ContractValidationError(f"scan record {index} has invalid SSID hex") from error
        security = record.get("security")
        require(security in SECURITY_ORDER, f"scan record {index} security invalid")
        require(0 <= len(ssid) <= 32, f"scan record {index} SSID length invalid")
        require(type(record.get("rssi")) is int and -128 <= record["rssi"] <= 127,
                f"scan record {index} RSSI invalid")
        require(type(record.get("channel")) is int and 1 <= record["channel"] <= 14,
                f"scan record {index} channel invalid")
        require_exact_type(record.get("saved"), bool, f"scan record {index} saved")
        if not ssid:
            continue
        candidate = {
            "ssid_hex": ssid.hex(),
            "security": security,
            "rssi": record["rssi"],
            "channel": record["channel"],
            "saved": record["saved"],
        }
        key = (ssid, SECURITY_ORDER[security])
        current = normalized.get(key)
        if current is None or candidate["rssi"] > current["rssi"]:
            normalized[key] = candidate

    ordered = sorted(
        normalized.values(),
        key=lambda record: (
            -record["rssi"],
            bytes.fromhex(record["ssid_hex"]),
            SECURITY_ORDER[record["security"]],
        ),
    )
    return ordered[:capacity], len(ordered) > capacity


def validate_scan(root: Path) -> None:
    fixture = load_json(root, "fixtures/scan/normalization-v1.json")
    require_exact_type(fixture, dict, "scan normalization fixture")
    records, truncated = normalize_scan_records(
        fixture.get("input"), fixture.get("capacity")
    )
    require(records == fixture.get("expected"), "scan normalization mismatch")
    require(truncated is fixture.get("truncated"), "scan truncation mismatch")


def validate_semantics(root: Path) -> None:
    semantic = load_json(root, "fixtures/semantic-cases.json")
    require_exact_type(semantic, list, "semantic fixture")
    ids = [case.get("id") for case in semantic if type(case) is dict]
    require(len(ids) == len(semantic), "every semantic case needs an id")
    require(len(set(ids)) == len(ids), "duplicate semantic case id")
    require(set(ids) == SEMANTIC_CASES, "semantic case coverage mismatch")
    cases = {case["id"]: case for case in semantic}
    require(cases["poll-terminal-refresh"] == {
        "id": "poll-terminal-refresh",
        "poll_interval_ms": 500,
        "final_snapshot_required": True,
    }, "polling semantic mismatch")
    require(cases["events-unadvertised"] == {
        "id": "events-unadvertised",
        "event_feature": False,
        "proto_ver_capability": False,
        "event_characteristic": False,
        "subscribe_result": "UNSUPPORTED_OPERATION",
        "polling_complete": True,
    }, "unadvertised event fallback mismatch")
    require(cases["events-low-mtu"]["negotiated_mtu"] == 184 and
            cases["events-low-mtu"]["subscribe_result"] == "OK" and
            not cases["events-low-mtu"]["notifications_enabled"] and
            cases["events-low-mtu"]["empty_key_material"] and
            cases["events-low-mtu"]["current_snapshot"],
            "low-MTU event fallback mismatch")
    require(cases["events-cccd-disabled"]["negotiated_mtu"] == 185 and
            not cases["events-cccd-disabled"]["cccd_enabled"] and
            cases["events-cccd-disabled"]["subscribe_result"] == "OK" and
            not cases["events-cccd-disabled"]["notifications_enabled"] and
            cases["events-cccd-disabled"]["empty_key_material"] and
            cases["events-cccd-disabled"]["current_snapshot"],
            "disabled-CCCD event fallback mismatch")
    require(cases["events-enabled"]["negotiated_mtu"] == 185 and
            cases["events-enabled"]["cccd_enabled"] and
            cases["events-enabled"]["subscribe_result"] == "OK" and
            cases["events-enabled"]["notifications_enabled"] and
            cases["events-enabled"]["key_material_present"] and
            cases["events-enabled"]["current_snapshot"],
            "event MTU boundary mismatch")
    require(not cases["cancel-active"]["creates_operation"],
            "cancel must not create an operation")
    require(cases["cancel-completion-race"] == {
        "id": "cancel-completion-race",
        "possible_result": ["ORIGINAL_TERMINAL", "CANCELED"],
        "exactly_one_terminal": True,
        "cancel_creates_operation": False,
    }, "cancel completion race mismatch")
    require(cases["scan-stored-before-terminal"]["result_stored_before_terminal"],
            "scan result publication order mismatch")
    require(cases["scan-latest-generation-zero"] == {
        "id": "scan-latest-generation-zero",
        "requested_generation": 0,
        "result": "LATEST_COMPLETED",
    }, "latest scan recovery mismatch")
    require(cases["scan-unavailable-generation-zero"] == {
        "id": "scan-unavailable-generation-zero",
        "requested_generation": 0,
        "result": "NOT_FOUND",
    }, "missing scan recovery mismatch")
    require(cases["storage-connected-not-persisted"] == {
        "id": "storage-connected-not-persisted",
        "result": "FAILED",
        "failure": "STORAGE",
        "state": "CONNECTED",
        "has_ipv4": True,
        "saved_profile": True,
        "profile_persisted": False,
    }, "connected storage failure mismatch")
    require(cases["snapshot-connected"] == {
        "id": "snapshot-connected",
        "state": "CONNECTED",
        "failure": "NONE",
        "has_ipv4": True,
    }, "connected snapshot invariant mismatch")
    require(cases["snapshot-unsaved-target"] == {
        "id": "snapshot-unsaved-target",
        "saved_profile": True,
        "profile_persisted": False,
        "ssid_source": "ACTIVE_TARGET",
    }, "snapshot SSID precedence mismatch")


def validate_wire_limits(root: Path, registry: DescriptorRegistry) -> tuple[int, int]:
    limits = load_json(root, "fixtures/wire-limits-v1.json")
    require_exact_type(limits, dict, "wire limits fixture")
    require(limits.get("max_scan_records") == 5, "scan record limit mismatch")
    require(limits.get("max_ssid_bytes") == 32, "SSID limit mismatch")
    require(limits.get("max_password_bytes") == 63, "password limit mismatch")
    require(limits.get("minimum_event_mtu") == 185, "event MTU mismatch")

    maximum_u64 = (1 << 64) - 1
    event = registry.message_class(PROTO_PREFIX + "ProvisioningEvent")()
    event.generation = maximum_u64
    snapshot = event.snapshot
    snapshot.generation = maximum_u64
    snapshot.state = 8
    snapshot.failure = 10
    snapshot.ssid = b"S" * limits["max_ssid_bytes"]
    snapshot.has_ipv4 = True
    snapshot.saved_profile = True
    snapshot.profile_persisted = True
    snapshot.auto_connect = True
    snapshot.manual_hold = True
    snapshot.last_operation.operation_id = maximum_u64
    snapshot.last_operation.type = 6
    snapshot.last_operation.state = 4
    snapshot.last_operation.failure = 10
    plaintext = event.SerializeToString(deterministic=True)

    frame = registry.message_class(PROTO_PREFIX + "EncryptedEventFrame")()
    frame.subscription_id = (1 << 32) - 1
    frame.sequence = maximum_u64
    frame.ciphertext = b"C" * len(plaintext)
    frame.tag = b"T" * 16
    event_frame_size = len(frame.SerializeToString(deterministic=True))
    require(event_frame_size <= limits["maximum_event_frame_bytes"],
            f"event frame exceeds limit: {event_frame_size}")

    response = registry.message_class(PROTO_PREFIX + "ProvisioningResponse")()
    response.request_id = maximum_u64
    response.code = 1
    response.failure = 1
    response.scan_results.generation = maximum_u64
    for index in range(limits["max_scan_records"]):
        network = response.scan_results.networks.add()
        network.ssid = bytes([ord("A") + index]) * limits["max_ssid_bytes"]
        network.rssi = -128
        network.channel = 14
        network.security = 3
        network.saved = True
    response.scan_results.truncated = True
    encrypted_response_size = (
        len(response.SerializeToString(deterministic=True))
        + limits["security2_tag_bytes"]
    )
    require(encrypted_response_size <= limits["maximum_encrypted_response_bytes"],
            f"encrypted scan response exceeds limit: {encrypted_response_size}")
    return event_frame_size, encrypted_response_size


def validate_stress_session_payload(payload: Any) -> None:
    require_exact_type(payload, dict, "stress session")
    require(set(payload) == {
        "schema",
        "transport",
        "security",
        "bootstrap_requests",
        "steady_request",
        "interval_ms",
        "maximum_idle_ms",
        "maximum_in_flight",
        "request_id",
        "forbidden_steady_requests",
        "steady_disconnects",
        "steady_reconnects",
        "blind_retry",
    }, "stress session fields mismatch")
    require(payload["schema"] == 1, "stress session schema must be 1")
    require(payload["transport"] == "ble", "stress transport must be ble")
    require_exact_type(payload["security"], int, "stress security")
    require(payload["security"] == 2, "stress security must be 2")
    require(payload["bootstrap_requests"] == ["get_capabilities"],
            "stress bootstrap request mismatch")
    require(payload["steady_request"] == "get_snapshot",
            "stress steady request must be get_snapshot")
    require_exact_type(payload["interval_ms"], int, "stress interval_ms")
    require(payload["interval_ms"] == 2000,
            "stress request interval must be 2000 ms")
    require_exact_type(payload["maximum_idle_ms"], int,
                       "stress maximum_idle_ms")
    require(payload["maximum_idle_ms"] == 10000,
            "stress maximum idle must be 10000 ms")
    require_exact_type(payload["maximum_in_flight"], int,
                       "stress maximum_in_flight")
    require(payload["maximum_in_flight"] == 1,
            "stress requests must be serial")
    request_id = payload["request_id"]
    require_exact_type(request_id, dict, "stress request_id")
    require(set(request_id) == {
        "nonzero",
        "unique_per_session",
        "retry_reuses_id",
    }, "stress request-id fields mismatch")
    for name in ("nonzero", "unique_per_session", "retry_reuses_id"):
        require_exact_type(request_id[name], bool,
                           f"stress request_id.{name}")
    require(request_id == {
        "nonzero": True,
        "unique_per_session": True,
        "retry_reuses_id": False,
    }, "stress request-id policy mismatch")
    require(payload["forbidden_steady_requests"] ==
            STRESS_FORBIDDEN_REQUESTS,
            "stress forbidden request list mismatch")
    require_exact_type(payload["steady_disconnects"], int,
                       "stress steady_disconnects")
    require_exact_type(payload["steady_reconnects"], int,
                       "stress steady_reconnects")
    require(payload["steady_disconnects"] == 0 and
            payload["steady_reconnects"] == 0,
            "stress steady connection must remain open")
    require_exact_type(payload["blind_retry"], bool, "stress blind_retry")
    require(not payload["blind_retry"], "stress blind retry must be disabled")


def validate_stress_session(root: Path) -> None:
    validate_stress_session_payload(
        load_json(root, "fixtures/stress-session-v1.json")
    )


def _valid_commit(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def validate_compatibility(root: Path, version: str) -> None:
    manifest = load_yaml(root, "compatibility/known-good.yaml")
    require_exact_type(manifest, dict, "compatibility manifest")
    require(manifest.get("schema") == 1, "compatibility schema must be 1")
    combinations = manifest.get("combinations")
    require_exact_type(combinations, list, "compatibility combinations")
    require(bool(combinations), "compatibility combinations cannot be empty")
    ids = [entry.get("id") for entry in combinations if type(entry) is dict]
    require(len(ids) == len(combinations), "every compatibility entry needs an id")
    require(len(set(ids)) == len(ids), "duplicate compatibility id")
    current_draft = False
    for entry in combinations:
        require(entry.get("status") in {"draft", "verified"},
                f"invalid compatibility status: {entry.get('id')}")
        contract = entry.get("contract")
        android = entry.get("android")
        device = entry.get("device")
        require_exact_type(contract, dict, f"contract entry {entry.get('id')}")
        require_exact_type(android, dict, f"android entry {entry.get('id')}")
        require_exact_type(device, dict, f"device entry {entry.get('id')}")
        require(re.fullmatch(r"0\.[0-9]+\.[0-9]+", str(contract.get("version"))) is not None,
                f"invalid contract version: {entry.get('id')}")
        require(android.get("repository") == "MingYuan0415/mt-android-app",
                f"invalid Android repository: {entry.get('id')}")
        require(device.get("repository") == "MingYuan0415/mt-device",
                f"invalid device repository: {entry.get('id')}")
        notes = entry.get("notes")
        require(type(notes) is list and notes and
                all(type(note) is str and note for note in notes),
                f"invalid compatibility notes: {entry.get('id')}")
        if entry["status"] == "draft":
            require(contract.get("commit") == "pending" and
                    android.get("commit") == "pending" and
                    device.get("commit") == "pending",
                    f"draft commits must be pending: {entry.get('id')}")
            require(entry.get("verified_at") is None,
                    f"draft verified_at must be null: {entry.get('id')}")
            if str(contract.get("version")) == version:
                current_draft = True
        else:
            require(_valid_commit(contract.get("commit")) and
                    _valid_commit(android.get("commit")) and
                    _valid_commit(device.get("commit")),
                    f"verified commits must be full SHAs: {entry.get('id')}")
            require_exact_type(entry.get("verified_at"), str,
                               f"verified_at {entry.get('id')}")
            try:
                datetime.fromisoformat(entry["verified_at"].replace("Z", "+00:00"))
            except ValueError as error:
                raise ContractValidationError(
                    f"invalid verified_at: {entry.get('id')}"
                ) from error
    require(current_draft, "current contract version needs a draft combination")


def validate_release(root: Path) -> str:
    try:
        version = (root / "VERSION").read_text(encoding="ascii").strip()
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ContractValidationError(f"cannot read release metadata: {error}") from error
    require(version == "0.1.2", "contract VERSION must be 0.1.2")
    require(f"## [{version}] - " in changelog, "VERSION is missing from CHANGELOG")
    return version


def validate_markdown_links(root: Path) -> None:
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in [root / "README.md", *sorted((root / "docs").glob("*.md"))]:
        text = path.read_text(encoding="utf-8")
        for target in link_pattern.findall(text):
            if target.startswith(("http://", "https://", "#")):
                continue
            relative = target.split("#", 1)[0]
            if not relative:
                continue
            require((path.parent / relative).resolve().exists(),
                    f"broken Markdown link in {path.relative_to(root)}: {target}")


def validate_all_json(root: Path) -> None:
    for path in sorted((root / "fixtures").rglob("*.json")):
        load_json(root, str(path.relative_to(root)))


def run(root: Path, descriptor_path: Path | None = None) -> tuple[int, int]:
    validate_all_json(root)
    version = validate_release(root)
    registry = DescriptorRegistry(build_descriptor_set(root, descriptor_path))
    validate_protobuf(root, registry)
    validate_qr(root)
    validate_proto_version(root)
    validate_crypto(root)
    validate_request_matrix(root, registry)
    validate_scan(root)
    validate_semantics(root)
    sizes = validate_wire_limits(root, registry)
    validate_stress_session(root)
    validate_compatibility(root, version)
    validate_markdown_links(root)
    return sizes


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate provisioning contract fixtures")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--descriptor-set", type=Path)
    arguments = parser.parse_args()
    try:
        event_size, response_size = run(
            arguments.root.resolve(), arguments.descriptor_set
        )
    except ContractValidationError as error:
        print(f"contract validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "contract fixtures valid: "
        f"event_frame={event_size} encrypted_scan_response={response_size}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
