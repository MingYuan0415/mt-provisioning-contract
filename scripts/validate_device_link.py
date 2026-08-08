from __future__ import annotations

import base64
import binascii
import re
import struct
import sys
from pathlib import Path
from typing import Any

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from google.protobuf import json_format
from google.protobuf.message import DecodeError

from scripts.validate_fixtures import ContractValidationError
from scripts.validate_fixtures import DescriptorRegistry
from scripts.validate_fixtures import load_json
from scripts.validate_fixtures import load_yaml
from scripts.validate_fixtures import require
from scripts.validate_fixtures import require_exact_type

LINK_PROTO_PREFIX = "microtech.link.v1."
LINK_PROFILE = "profiles/device-link-v1.yaml"
LINK_PROFILE_CONSISTENCY = "fixtures/profile/device-link-consistency-v1.json"
LINK_FRAMING = "fixtures/framing/framing-v1.json"
LINK_SECURITY = "fixtures/semantic/device-link-security-v1.json"
LINK_SESSION_TRANSPORT = "fixtures/semantic/device-link-session-transport-v1.json"
LINK_GOLDEN = "fixtures/protobuf/link-golden-v1.json"
LINK_INVALID = "fixtures/protobuf/link-invalid-v1.json"
LINK_ADVERTISING = "fixtures/discovery/advertising-v1.json"
LINK_LIMITS = "fixtures/link-limits-v1.json"
LINK_QR_VALID = "fixtures/qr/device-link-valid-v1.json"
LINK_QR_INVALID = "fixtures/qr/device-link-invalid-v1.json"

LINK_QR_FIELDS = {"ver", "name", "service", "discriminator", "pop",
                  "expires_in_ms"}
LINK_QR_VERSION = "link-v1"
LINK_QR_SHORT_NAME = "MT"

FRAMING_VERSION = 1
HEADER_BYTES = 8
FLAG_START = 0x01
FLAG_END = 0x02
U16_MAX = 0xFFFF

UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CHARACTERISTIC_PROPERTIES = {
    "read",
    "write",
    "write_without_response",
    "notify",
    "indicate",
}

SECURITY_SEMANTICS = {
    "prepare-without-commit-clears": {
        "authorization_persisted": False,
        "provisional_bond_cleared": True,
        "recovery_state": "UNBOUND",
    },
    "commit-nvs-failure-keeps-unbound": {
        "authorization_persisted": False,
        "error_class": "STORAGE",
        "recovery_state": "UNBOUND",
    },
    "commit-response-lost-authenticated": {
        "authorization_persisted": True,
        "client_recovery": "TEST_LONG_TERM_CREDENTIAL",
        "recovery_state": "AUTHORIZED",
    },
    "lost-commit-response-query-recovers": {
        "authorization_persisted": True,
        "recovery": "GET_AUTHORIZATION_WITH_RECOVERY_QUERY",
        "device_authorization_id_restored": True,
        "recovery_state": "AUTHORIZED",
    },
    "get-authorization-wrong-credential-rejected": {
        "credential_match": False,
        "result": "REJECTED",
        "recovery_state": "UNCHANGED",
    },
    "prepare-refetch-same-transaction": {
        "fresh_request_id": True,
        "same_txn_id": True,
        "same_credential_id": True,
        "same_application_password": True,
    },
    "idempotent-authorize-commit": {
        "retry_with_same_txn": True,
        "exactly_one_record": True,
        "recovery_state": "AUTHORIZED",
    },
    "bond-without-authorization-deleted": {
        "orphan_bond_removed": True,
        "recovery_state": "UNBOUND",
    },
    "authorization-without-bond-invalidated": {
        "record_invalidated": True,
        "requires_binding_window": True,
    },
    "app-credential-lost-requires-rebind": {
        "fallback_to_bond_only": False,
        "requires_local_confirmation": True,
    },
    "wrong-app-credential-rejected": {
        "handshake_result": "REJECTED",
        "recovery_state": "UNCHANGED",
    },
    "replacement-crash-unbound-not-dual": {
        "old_authorization_invalidated_before_bond_deleted": True,
        "worst_state": "UNBOUND",
    },
    "local-revoke-journal-recoverable": {
        "journaled": True,
        "resume": "BEFORE_ADVERTISING_AND_AUTOCONNECT",
        "worst_state": "UNBOUND",
    },
    "factory-reset-journal-recoverable": {
        "journaled": True,
        "authorization": "CLEARED",
        "bond": "CLEARED",
        "cccd": "CLEARED",
        "wifi_profile": "CLEARED",
    },
    "unknown-peer-outside-window-rejected": {
        "pairing_allowed": False,
        "connection_result": "REJECTED",
    },
    "second-acl-rejected": {
        "admitted": False,
        "existing_link_preserved": True,
    },
    "factory-reset-clears-all": {
        "authorization": "CLEARED",
        "bond": "CLEARED",
        "cccd": "CLEARED",
        "wifi_profile": "CLEARED",
        "transfer": "CLEARED",
    },
    "late-callback-ignored": {
        "generation": "STALE",
        "effect": "NONE",
    },
    "restored-cccd-not-authorizing": {
        "tx_allowed_before_authorization": False,
        "snapshot_after_authorization": True,
    },
    "sc-only-no-legacy": {
        "legacy_pairing": False,
        "key_size_bytes": 16,
        "maximum_bonds": 1,
    },
    "identity-key-not-rpa": {
        "identity_key": "ADDRESS_TYPE_AND_VALUE",
        "forbidden_keys": ["OTA_ADDRESS", "CONN_HANDLE", "IRK_HASH", "DISCRIMINATOR"],
    },
    "indication-timeout-closes-session": {
        "session_closed": True,
        "next_request_allowed": False,
        "recovery": "NEW_SESSION_AND_QUERY",
    },
    "ambiguous-mutation-queries-first": {
        "blind_retry": False,
        "recovery": "QUERY_SNAPSHOT_OR_OPERATION",
    },
    "event-gap-snapshot-recovery": {
        "gap_action": "FETCH_FULL_SNAPSHOT",
        "replay_infinite_history": False,
    },
    "boot-id-resets-sequence": {
        "event_sequence_scope": "BOOT",
        "request_id_scope": "SESSION",
        "operation_id_scope": "BOOT",
        "transfer_id_scope": "TRANSFER_LIFETIME",
    },
    "duplicate-request-id-conflict": {
        "result": "LINK_ERROR_CONFLICT",
        "recovery": "FRESH_REQUEST_ID_OR_QUERY",
    },
    "event-sequence-no-wrap": {
        "wrap": False,
        "max_reached_action": "STOP_PUBLICATION_UNTIL_REBOOT",
    },
    "snapshot-atomic-baseline": {
        "sequence_baseline_equals_snapshot_sequence": True,
        "events_start_at": "BASELINE_PLUS_ONE",
    },
}


def _decode_hex(value: Any, name: str) -> bytes:
    require_exact_type(value, str, name)
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ContractValidationError(f"invalid hex in {name}") from error


def validate_link_profile(root: Path) -> None:
    profile = load_yaml(root, LINK_PROFILE)
    require_exact_type(profile, dict, "Device Link profile")
    require(profile.get("schema") == 1, "profile schema must be 1")
    require(profile.get("status") == "draft", "profile status must be draft")
    require(profile.get("protocol_package") == "microtech.link.v1",
            "profile protocol package mismatch")
    require(profile.get("preferred_att_mtu") == 498,
            "preferred ATT MTU must be 498")

    framing = profile.get("framing")
    require_exact_type(framing, dict, "profile framing")
    require(framing.get("version") == FRAMING_VERSION,
            "framing version mismatch")
    require(framing.get("header_bytes") == HEADER_BYTES,
            "framing header size mismatch")
    require(framing.get("byte_order") == "little",
            "framing byte order must be little")

    session_transport = profile.get("session_transport")
    require_exact_type(session_transport, dict, "profile session_transport")
    require(session_transport.get("type_bytes") == 1,
            "session transport type size must be 1")
    require(session_transport.get("handshake_type") == 0,
            "session transport handshake type must be 0")
    require(session_transport.get("encrypted_type") == 1,
            "session transport encrypted type must be 1")

    qr = profile.get("qr")
    require_exact_type(qr, dict, "profile qr")
    require(qr.get("version") == LINK_QR_VERSION,
            "profile QR version mismatch")
    require(qr.get("short_name") == LINK_QR_SHORT_NAME,
            "profile QR short name mismatch")
    require(qr.get("pop_bytes") == 16, "profile QR pop must be 16 bytes")
    require(qr.get("discriminator_bytes") == 3,
            "profile QR discriminator must be 3 bytes")
    require(qr.get("expires_in_ms_max") == 3600000,
            "profile QR expiry bound mismatch")

    security = profile.get("security")
    require_exact_type(security, dict, "profile security")
    require(security.get("le_secure_connections_only") is True,
            "Secure Connections only is required")
    require(security.get("encryption_key_bytes") == 16,
            "encryption key must be 16 bytes")
    require(security.get("maximum_bonds") == 1, "maximum bonds must be 1")
    require(security.get("protocomm_security_version") == 2,
            "Protocomm security version must be 2")
    require(security.get("protocomm_security_patch_version") == 1,
            "Protocomm security patch must be 1")
    require(security.get("local_confirmation_required") is True,
            "local confirmation is required")
    require(security.get("application_credential_required") is True,
            "application credential is required")

    services = profile.get("services")
    require_exact_type(services, list, "profile services")
    require(len(services) == 2, "Device Link must define two services")
    service_uuids = set()
    characteristic_uuids = set()
    names = set()
    for service in services:
        service_uuid = service.get("uuid")
        require(UUID_PATTERN.fullmatch(service_uuid) is not None,
                f"invalid service UUID {service_uuid}")
        require(service_uuid not in service_uuids, "duplicate service UUID")
        service_uuids.add(service_uuid)
        characteristics = service.get("characteristics")
        require_exact_type(characteristics, list,
                           f"characteristics of {service.get('name')}")
        for characteristic in characteristics:
            name = characteristic.get("name")
            require(name is not None and name not in names,
                    "duplicate characteristic name")
            names.add(name)
            characteristic_uuid = characteristic.get("uuid")
            require(UUID_PATTERN.fullmatch(characteristic_uuid) is not None,
                    f"invalid characteristic UUID {characteristic_uuid}")
            require(characteristic_uuid not in characteristic_uuids,
                    "duplicate characteristic UUID")
            characteristic_uuids.add(characteristic_uuid)
            properties = characteristic.get("properties")
            require_exact_type(properties, list,
                               f"properties of {name}")
            require(bool(properties), f"empty properties on {name}")
            require(set(properties) <= CHARACTERISTIC_PROPERTIES,
                    f"unknown property on {name}")

    consistency = load_json(root, LINK_PROFILE_CONSISTENCY)
    require_exact_type(consistency, dict, "profile consistency fixture")
    require(consistency.get("preferred_att_mtu") ==
            profile.get("preferred_att_mtu"),
            "profile consistency MTU mismatch")
    require(consistency.get("protocol_package") ==
            profile.get("protocol_package"),
            "profile consistency package mismatch")
    require(consistency.get("framing") == framing,
            "profile consistency framing mismatch")
    require(consistency.get("security") == security,
            "profile consistency security mismatch")
    require(consistency.get("services") == services,
            "profile consistency services mismatch")
    require(consistency.get("timeouts") == profile.get("timeouts"),
            "profile consistency timeouts mismatch")
    require(consistency.get("advertising") == profile.get("advertising"),
            "profile consistency advertising mismatch")
    require(consistency.get("session_transport") == session_transport,
            "profile consistency session_transport mismatch")
    require(consistency.get("qr") == qr,
            "profile consistency qr mismatch")


def parse_fragment(value: bytes) -> tuple[int, int, int, int, int, bytes]:
    require(len(value) >= HEADER_BYTES, "fragment shorter than header")
    version, flags, frame_id, total_length, offset = struct.unpack(
        "<BBHHH", value[:HEADER_BYTES]
    )
    require(version == FRAMING_VERSION, "unsupported framing version")
    require(flags & ~(FLAG_START | FLAG_END) == 0, "unknown flag bit")
    require(frame_id != 0, "zero frame ID")
    require(total_length != 0, "zero total length")
    return version, flags, frame_id, total_length, offset, value[HEADER_BYTES:]


class FragmentReassembler:
    """Reference reassembler matching the Device Link framing contract."""

    def __init__(self) -> None:
        self._frame_id: int | None = None
        self._total_length: int | None = None
        self._next_offset = 0
        self._buffer = bytearray()
        self._last_value: bytes | None = None
        self._complete = False
        self._delivered = False

    def feed(self, value: bytes) -> bytes | None:
        if self._complete:
            raise ContractValidationError("frame already complete")
        if self._last_value is not None and value == self._last_value:
            return None
        version, flags, frame_id, total_length, offset, payload = parse_fragment(
            value
        )
        if self._frame_id is None:
            require(bool(flags & FLAG_START), "first fragment lacks START")
            require(offset == 0, "first fragment offset must be zero")
            require(bool(payload), "first fragment payload must not be empty")
            self._frame_id = frame_id
            self._total_length = total_length
        else:
            require(frame_id == self._frame_id, "frame ID changed mid-frame")
            require(flags & FLAG_START == 0, "unexpected START flag")
            require(total_length == self._total_length,
                    "total length changed mid-frame")
            require(offset >= self._next_offset, "fragment overlap")
            require(offset == self._next_offset, "fragment gap")
        require(offset + len(payload) <= self._total_length,
                "fragment exceeds total length")
        require(bool(payload), "empty fragment payload")
        if flags & FLAG_END:
            require(offset + len(payload) == self._total_length,
                    "END flag does not match total length")
        else:
            require(offset + len(payload) < self._total_length,
                    "fragment fills message without END")
        self._buffer.extend(payload)
        self._next_offset = offset + len(payload)
        self._last_value = value
        if flags & FLAG_END:
            self._complete = True
            require(not self._delivered, "frame delivered twice")
            self._delivered = True
            return bytes(self._buffer)
        return None


def validate_link_framing(root: Path) -> None:
    fixture = load_json(root, LINK_FRAMING)
    require_exact_type(fixture, dict, "framing fixture")
    require(fixture.get("schema") == 1, "framing fixture schema must be 1")
    require(fixture.get("framing_version") == FRAMING_VERSION,
            "framing fixture version mismatch")
    require(fixture.get("header_bytes") == HEADER_BYTES,
            "framing fixture header mismatch")
    require(fixture.get("flags") == {"start": FLAG_START, "end": FLAG_END},
            "framing flag values mismatch")

    boundaries = fixture.get("mtu_boundaries")
    require_exact_type(boundaries, list, "framing MTU boundaries")
    require(boundaries == [
        {"att_mtu": 23, "write_value_bytes": 20, "framing_payload_bytes": 12},
        {"att_mtu": 185, "write_value_bytes": 182, "framing_payload_bytes": 174},
        {"att_mtu": 498, "write_value_bytes": 495, "framing_payload_bytes": 487},
    ], "framing MTU arithmetic mismatch")
    for boundary in boundaries:
        require(boundary["write_value_bytes"] == boundary["att_mtu"] - 3,
                "ATT value arithmetic mismatch")
        require(boundary["framing_payload_bytes"] ==
                boundary["write_value_bytes"] - HEADER_BYTES,
                "framing payload arithmetic mismatch")

    payload_capacity = {
        boundary["att_mtu"]: boundary["framing_payload_bytes"]
        for boundary in boundaries
    }
    for case in fixture.get("valid_frames"):
        values = case.get("values")
        require_exact_type(values, list, f"valid frame values {case.get('id')}")
        require(bool(values), f"empty valid frame {case.get('id')}")
        capacity = payload_capacity[case["max_att_mtu"]]
        total_payload = 0
        previous: bytes | None = None
        for value in values:
            decoded = _decode_hex(value, case["id"])
            if decoded == previous:
                continue
            payload_length = len(decoded) - HEADER_BYTES
            require(payload_length >= 0, f"short value in {case.get('id')}")
            require(payload_length <= capacity,
                    f"payload exceeds MTU in {case.get('id')}")
            total_payload += payload_length
            previous = decoded
        require(total_payload == case["total_length"],
                f"payload total mismatch in {case.get('id')}")
        reassembler = FragmentReassembler()
        delivered: bytes | None = None
        for value in values:
            result = reassembler.feed(_decode_hex(value, case["id"]))
            if result is not None:
                require(delivered is None, f"double delivery in {case.get('id')}")
                delivered = result
        require(delivered is not None, f"valid frame never completed: {case.get('id')}")
        require(len(delivered) == case["total_length"],
                f"delivered length mismatch in {case.get('id')}")

    for case in fixture.get("invalid_fragments"):
        values = case.get("values")
        require_exact_type(values, list, f"invalid values {case.get('id')}")
        reassembler = FragmentReassembler()
        rejected = False
        for value in values:
            try:
                reassembler.feed(_decode_hex(value, case["id"]))
            except ContractValidationError:
                rejected = True
                break
        require(rejected, f"invalid frame passed: {case.get('id')}")


def validate_link_security_semantics(root: Path) -> None:
    semantic = load_json(root, LINK_SECURITY)
    require_exact_type(semantic, list, "security semantic fixture")
    ids = [case.get("id") for case in semantic if type(case) is dict]
    require(len(ids) == len(semantic), "every security case needs an id")
    require(len(set(ids)) == len(ids), "duplicate security case id")
    require(set(ids) == set(SECURITY_SEMANTICS),
            "security semantic coverage mismatch")
    cases = {case["id"]: case for case in semantic}
    for case_id, expected in SECURITY_SEMANTICS.items():
        require(cases[case_id] == {"id": case_id, **expected},
                f"security semantic mismatch: {case_id}")


def validate_link_protobuf(root: Path, registry: DescriptorRegistry) -> None:
    golden = load_json(root, LINK_GOLDEN)
    require_exact_type(golden, list, "link protobuf golden fixture")
    ids = [case.get("id") for case in golden if type(case) is dict]
    require(len(ids) == len(golden), "every link golden case needs an id")
    require(len(set(ids)) == len(ids), "duplicate link golden id")
    for case in golden:
        full_name = case.get("type")
        require(type(full_name) is str and full_name.startswith(LINK_PROTO_PREFIX),
                f"invalid link protobuf type in {case.get('id')}")
        payload = _decode_hex(case.get("hex", ""), case["id"])
        require(payload, f"empty link protobuf payload in {case.get('id')}")
        message = registry.message_class(full_name)()
        try:
            message.ParseFromString(payload)
        except DecodeError as error:
            raise ContractValidationError(
                f"link golden protobuf did not parse: {case.get('id')}"
            ) from error
        require(json_format.MessageToDict(
            message, preserving_proto_field_name=True) == case.get("json"),
            f"decoded link protobuf mismatch: {case.get('id')}")
        require(message.SerializeToString(deterministic=True) == payload,
                f"link protobuf is not canonical: {case.get('id')}")

    invalid = load_json(root, LINK_INVALID)
    require_exact_type(invalid, list, "link invalid protobuf fixture")
    invalid_ids = [case.get("id") for case in invalid if type(case) is dict]
    require(len(invalid_ids) == len(invalid),
            "every link invalid case needs an id")
    require(len(set(invalid_ids)) == len(invalid_ids),
            "duplicate link invalid id")
    for case in invalid:
        message = registry.message_class(case.get("type", ""))()
        try:
            payload = _decode_hex(case.get("hex", ""), case["id"])
            message.ParseFromString(payload)
        except (ValueError, DecodeError):
            continue
        raise ContractValidationError(
            f"invalid link protobuf parsed successfully: {case.get('id')}"
        )


def validate_link_advertising(root: Path) -> None:
    fixture = load_json(root, LINK_ADVERTISING)
    require_exact_type(fixture, dict, "advertising fixture")
    require(fixture.get("schema") == 1, "advertising fixture schema must be 1")
    require(fixture.get("advertising_version") == 1,
            "advertising version mismatch")
    require(fixture.get("short_name") == "MT", "short name mismatch")
    profile = load_yaml(root, LINK_PROFILE)
    profile_advertising = profile.get("advertising")
    require_exact_type(profile_advertising, dict, "profile advertising")
    profile_uuid = profile_advertising.get("service_data", {}).get("uuid")
    require(fixture.get("service_uuid") == profile_uuid,
            "advertising fixture UUID mismatch with profile")
    require(fixture.get("flags") == {"bindable": 1},
            "advertising flags mismatch")
    require(fixture.get("discriminator_bytes") == 3,
            "discriminator size mismatch")
    require(fixture.get("max_payload_bytes") == 31,
            "advertising payload limit mismatch")

    service_uuid_le = bytes(reversed(
        bytes.fromhex(fixture["service_uuid"].replace("-", ""))))
    for case in fixture.get("valid_payloads"):
        payload = _decode_hex(case.get("hex", ""), case["id"])
        require(len(payload) <= fixture["max_payload_bytes"],
                f"valid payload exceeds limit: {case.get('id')}")
        require(payload[0:3] == bytes.fromhex("020106"),
                f"flags AD missing in {case.get('id')}")
        service_data_len = payload[3]
        require(service_data_len == 1 + 16 + 1 + 1 + 3,
                f"service data length mismatch in {case.get('id')}")
        require(payload[4] == 0x21,
                f"service data AD type mismatch in {case.get('id')}")
        service_data = payload[5:5 + service_data_len - 1]
        require(service_data[0:16] == service_uuid_le,
                f"service data UUID mismatch in {case.get('id')}")
        require(service_data[16] == 1,
                f"advertising version mismatch in {case.get('id')}")
        expected_flags = 0x01 if case["bindable"] else 0x00
        require(service_data[17] == expected_flags,
                f"bindable flag mismatch in {case.get('id')}")
        discriminator = int.from_bytes(service_data[18:21],
                                       byteorder="little")
        require(discriminator == case["discriminator"],
                f"discriminator mismatch in {case.get('id')}")
        if not case["bindable"]:
            require(discriminator == 0,
                    f"bound state must not carry a discriminator: {case.get('id')}")
        else:
            require(discriminator != 0,
                    f"bindable state must carry a nonzero discriminator: {case.get('id')}")
        tail = payload[5 + service_data_len - 1:]
        require(tail == bytes.fromhex("03084d54"),
                f"short name AD mismatch in {case.get('id')}")

    for case in fixture.get("invalid_payloads"):
        try:
            payload = _decode_hex(case.get("hex", ""), case["id"])
        except ContractValidationError:
            continue
        rejected = False
        if len(payload) > fixture["max_payload_bytes"]:
            rejected = True
        elif len(payload) < 3 or payload[0:3] != bytes.fromhex("020106"):
            rejected = True
        elif len(payload) < 6 or payload[3] != 1 + 16 + 1 + 1 + 3:
            rejected = True
        elif len(payload) < 5 + payload[3] + 3:
            rejected = True
        else:
            service_data = payload[5:5 + payload[3] - 1]
            if payload[4] != 0x21:
                rejected = True
            elif service_data[0:16] != service_uuid_le:
                rejected = True
            elif service_data[16] != 1:
                rejected = True
            elif service_data[17] & ~0x01 != 0:
                rejected = True
            elif service_data[17] == 0 and \
                    int.from_bytes(service_data[18:21], byteorder="little") != 0:
                rejected = True
            elif service_data[17] == 1 and \
                    int.from_bytes(service_data[18:21], byteorder="little") == 0:
                rejected = True
            elif payload[5 + payload[3] - 1:] != bytes.fromhex("03084d54"):
                rejected = True
        require(rejected, f"invalid advertising payload passed: {case.get('id')}")


def _base64url_encode(data: bytes) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    output: list[str] = []
    for index in range(0, len(data) - 2, 3):
        value = (data[index] << 16) | (data[index + 1] << 8) | data[index + 2]
        output.append(alphabet[(value >> 18) & 0x3f])
        output.append(alphabet[(value >> 12) & 0x3f])
        output.append(alphabet[(value >> 6) & 0x3f])
        output.append(alphabet[value & 0x3f])
    remainder = len(data) % 3
    if remainder == 1:
        value = data[-1] << 16
        output.append(alphabet[(value >> 18) & 0x3f])
        output.append(alphabet[(value >> 12) & 0x3f])
    elif remainder == 2:
        value = (data[-2] << 16) | (data[-1] << 8)
        output.append(alphabet[(value >> 18) & 0x3f])
        output.append(alphabet[(value >> 12) & 0x3f])
        output.append(alphabet[(value >> 6) & 0x3f])
    return "".join(output)


def _decode_base64url(value: Any, expected_bytes: int, name: str) -> bytes:
    require_exact_type(value, str, name)
    require(re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None,
            f"{name} is not strict Base64URL")
    require(len(value) % 4 != 1, f"{name} has invalid Base64URL length")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise ContractValidationError(
            f"{name} is not strict Base64URL") from error
    require(len(decoded) == expected_bytes,
            f"{name} must decode to {expected_bytes} bytes")
    require(_base64url_encode(decoded) == value,
            f"{name} is not canonical Base64URL")
    return decoded


def validate_link_qr_payload(qr: Any) -> bytes:
    require_exact_type(qr, dict, "Device Link QR root")
    require(LINK_QR_FIELDS <= qr.keys(), "Device Link QR is missing a field")
    require(qr["ver"] == LINK_QR_VERSION,
            "Device Link QR version must be link-v1")
    require(qr["name"] == LINK_QR_SHORT_NAME,
            "Device Link QR name must be MT")
    service = qr["service"]
    profile = load_yaml(Path(__file__).resolve().parents[1], LINK_PROFILE)
    profile_uuid = profile["services"][0]["uuid"]
    require(service == profile_uuid,
            "Device Link QR service UUID mismatch with profile")
    require_exact_type(qr["expires_in_ms"], int,
                       "Device Link QR expires_in_ms")
    require(0 < qr["expires_in_ms"] <= 3600000,
            "Device Link QR expires_in_ms out of range")
    discriminator = _decode_base64url(
        qr["discriminator"], 3, "Device Link QR discriminator")
    require(discriminator != b"\x00\x00\x00",
            "Device Link QR discriminator must be nonzero")
    pop = _decode_base64url(qr["pop"], 16, "Device Link QR pop")
    require(pop != b"\x00" * 16, "Device Link QR pop must be nonzero")
    return discriminator


def validate_link_qr(root: Path) -> None:
    base = load_json(root, LINK_QR_VALID)
    discriminator = validate_link_qr_payload(base)
    with_unknown = dict(base)
    with_unknown["future"] = {"ignored": True}
    validate_link_qr_payload(with_unknown)

    advertising = load_json(root, LINK_ADVERTISING)
    window_case = next(
        (case for case in advertising["valid_payloads"]
         if case["bindable"]), None)
    require(window_case is not None,
            "advertising fixture needs a bindable payload")
    require(int.from_bytes(discriminator, byteorder="little") ==
            window_case["discriminator"],
            "QR discriminator does not match the advertising fixture")

    invalid = load_json(root, LINK_QR_INVALID)
    require_exact_type(invalid, list, "invalid Device Link QR fixture")
    ids = [case.get("id") for case in invalid if type(case) is dict]
    require(len(ids) == len(invalid), "every invalid Device Link QR needs an id")
    require(len(set(ids)) == len(ids),
            "duplicate invalid Device Link QR id")
    for case in invalid:
        candidate = dict(base)
        for field in case.get("remove", []):
            candidate.pop(field, None)
        candidate.update(case.get("replace", {}))
        try:
            validate_link_qr_payload(candidate)
        except ContractValidationError:
            continue
        raise ContractValidationError(
            f"invalid Device Link QR passed: {case.get('id')}")


SESSION_TRANSPORT_SEMANTICS = {
    "handshake-before-ciphertext": {
        "channel": "session", "type": 0, "session_state": "none",
        "binding_state": "window", "stage": "HANDSHAKE", "sec_version": 2,
        "proof_result": "OK", "result": "ACCEPTED",
        "session_after": "AUTHENTICATED", "response_channel": "session_tx",
        "response_type": 0,
    },
    "ciphertext-before-handshake": {
        "channel": "session", "type": 1, "session_state": "none",
        "binding_state": "window", "stage": "AUTHENTICATED",
        "ciphertext_len": 32, "counter_valid": True,
        "result": "REJECTED", "session_after": "CLOSED",
        "response_channel": None, "response_type": None,
    },
    "handshake-on-control": {
        "channel": "control", "type": 0, "session_state": "none",
        "binding_state": "bound", "stage": "HANDSHAKE", "sec_version": 2,
        "proof_result": "OK", "result": "REJECTED",
        "session_after": "CLOSED", "response_channel": None,
        "response_type": None,
    },
    "protected-on-control": {
        "channel": "control", "type": 1, "session_state": "authenticated",
        "binding_state": "bound", "stage": "AUTHENTICATED",
        "ciphertext_len": 64, "counter_valid": True,
        "authorization": "AUTHORIZED", "result": "ACCEPTED",
        "session_after": "AUTHENTICATED", "response_channel": "control_tx",
        "response_type": 1,
    },
    "protected-on-control-unauthenticated": {
        "channel": "control", "type": 1, "session_state": "authenticated",
        "binding_state": "bound", "stage": "AUTHENTICATED",
        "ciphertext_len": 64, "counter_valid": True,
        "authorization": "UNAUTHORIZED", "result": "REJECTED",
        "session_after": "CLOSED", "response_channel": None,
        "response_type": None,
    },
    "unknown-type": {
        "channel": "session", "type": 2, "session_state": "none",
        "binding_state": "window", "result": "REJECTED",
        "session_after": "CLOSED", "response_channel": None,
        "response_type": None,
    },
    "re-handshake-replaces": {
        "channel": "session", "type": 0, "session_state": "authenticated",
        "binding_state": "bound", "stage": "HANDSHAKE", "sec_version": 2,
        "proof_result": "OK", "replaces_transaction": True,
        "result": "ACCEPTED", "session_after": "AUTHENTICATED",
        "response_channel": "session_tx", "response_type": 0,
    },
    "malformed-handshake": {
        "channel": "session", "type": 0, "session_state": "none",
        "binding_state": "window", "stage": "HANDSHAKE", "sec_version": 2,
        "malformed": True, "result": "REJECTED", "session_after": "CLOSED",
        "response_channel": None, "response_type": None,
    },
    "wrong-sec-version": {
        "channel": "session", "type": 0, "session_state": "none",
        "binding_state": "window", "stage": "HANDSHAKE", "sec_version": 1,
        "result": "REJECTED", "session_after": "CLOSED",
        "response_channel": None, "response_type": None,
    },
    "short-ciphertext": {
        "channel": "session", "type": 1, "session_state": "authenticated",
        "binding_state": "bound", "stage": "AUTHENTICATED",
        "ciphertext_len": 8, "counter_valid": True,
        "result": "REJECTED", "session_after": "CLOSED",
        "response_channel": None, "response_type": None,
    },
    "failed-tag-closes": {
        "channel": "session", "type": 1, "session_state": "authenticated",
        "binding_state": "bound", "stage": "AUTHENTICATED",
        "ciphertext_len": 64, "counter_valid": True, "tag_valid": False,
        "result": "REJECTED", "session_after": "CLOSED",
        "response_channel": None, "response_type": None,
    },
    "wrong-credential-rejected": {
        "channel": "session", "type": 0, "session_state": "none",
        "binding_state": "bound", "stage": "HANDSHAKE", "sec_version": 2,
        "proof_result": "FAILED", "result": "REJECTED",
        "session_after": "CLOSED", "response_channel": None,
        "response_type": None,
    },
    "window-closed-no-verifier": {
        "channel": "session", "type": 0, "session_state": "none",
        "binding_state": "none", "stage": "HANDSHAKE", "sec_version": 2,
        "proof_result": "OK", "result": "NOT_ADMITTED",
        "session_after": "CLOSED", "response_channel": None,
        "response_type": None,
    },
    "bootstrap-verifier": {
        "channel": "session", "type": 0, "session_state": "none",
        "binding_state": "window", "stage": "HANDSHAKE", "sec_version": 2,
        "verifier": "QR_POP", "proof_result": "OK", "result": "ACCEPTED",
        "session_after": "AUTHENTICATED", "response_channel": "session_tx",
        "response_type": 0,
    },
    "bound-verifier": {
        "channel": "session", "type": 0, "session_state": "none",
        "binding_state": "bound", "stage": "HANDSHAKE", "sec_version": 2,
        "verifier": "LONG_TERM", "proof_result": "OK", "result": "ACCEPTED",
        "session_after": "AUTHENTICATED", "response_channel": "session_tx",
        "response_type": 0,
    },
    "replacement-window-bound-peer": {
        "channel": "session", "type": 0, "session_state": "none",
        "binding_state": "window_bound", "stage": "HANDSHAKE",
        "sec_version": 2, "verifier": "LONG_TERM", "proof_result": "OK",
        "result": "ACCEPTED", "session_after": "AUTHENTICATED",
        "response_channel": "session_tx", "response_type": 0,
    },
    "protected-response-routing": {
        "channel": "session", "type": 1, "session_state": "authenticated",
        "binding_state": "bound", "stage": "AUTHENTICATED",
        "ciphertext_len": 64, "counter_valid": True,
        "result": "ACCEPTED", "session_after": "AUTHENTICATED",
        "response_channel": "session_tx", "response_type": 1,
    },
    "get-capabilities-on-session-channel": {
        "channel": "session", "type": 1, "session_state": "authenticated",
        "binding_state": "window", "stage": "AUTHENTICATED",
        "ciphertext_len": 64, "counter_valid": True,
        "result": "ACCEPTED", "session_after": "AUTHENTICATED",
        "response_channel": "session_tx", "response_type": 1,
    },
    "get-authorization-recovery-query": {
        "channel": "session", "type": 1, "session_state": "authenticated",
        "binding_state": "bound", "stage": "AUTHENTICATED",
        "ciphertext_len": 64, "counter_valid": True,
        "recovery_query": True, "result": "ACCEPTED",
        "session_after": "AUTHENTICATED", "response_channel": "session_tx",
        "response_type": 1,
    },
    "authorize-prepare-on-control-rejected": {
        "channel": "control", "type": 1, "session_state": "authenticated",
        "binding_state": "window", "stage": "AUTHENTICATED",
        "ciphertext_len": 64, "counter_valid": True,
        "result": "REJECTED", "session_after": "CLOSED",
        "response_channel": None, "response_type": None,
    },
    "subscribe-events-unadvertised": {
        "channel": "control", "type": 1, "session_state": "authenticated",
        "binding_state": "bound", "stage": "AUTHENTICATED",
        "ciphertext_len": 64, "counter_valid": True,
        "authorization": "AUTHORIZED", "result": "UNSUPPORTED_OPERATION",
        "session_after": "AUTHENTICATED", "response_channel": "control_tx",
        "response_type": 1,
    },
}


def _require_session_transport_domain(expected: dict) -> None:
    """Value-domain checks beyond fixture equality."""
    case_id = expected["id"]
    channel = expected["channel"]
    frame_type = expected["type"]
    result = expected["result"]
    session_after = expected["session_after"]
    require(frame_type in {0, 1, 2}, f"invalid transport type in {case_id}")
    require(channel in {"session", "control"},
            f"invalid transport channel in {case_id}")
    require(session_after in {"HANDSHAKING", "AUTHENTICATED", "CLOSED"},
            f"invalid session outcome in {case_id}")
    if frame_type == 0:
        require(expected.get("stage") == "HANDSHAKE",
                f"handshake case must be HANDSHAKE stage: {case_id}")
        require(type(expected.get("sec_version")) is int,
                f"handshake case must carry sec_ver: {case_id}")
        proof = expected.get("proof_result")
        require(proof in {"OK", "FAILED", None},
                f"invalid proof result in {case_id}")
        if proof == "FAILED":
            require(result == "REJECTED",
                    f"failed proof must reject: {case_id}")
            require(session_after == "CLOSED",
                    f"failed proof must close: {case_id}")
        if result == "ACCEPTED":
            require(proof == "OK",
                    f"accepted handshake needs a verified proof: {case_id}")
            require(expected.get("sec_version") == 2,
                    f"accepted handshake needs sec_ver 2: {case_id}")
            require(session_after == "AUTHENTICATED",
                    f"verified proof must authenticate: {case_id}")
        if result == "NOT_ADMITTED":
            require(expected.get("binding_state") == "none",
                    f"non-admission only without a verifier: {case_id}")
        if result == "REJECTED" and proof is None:
            require(session_after == "CLOSED",
                    f"rejected handshake must close: {case_id}")
        require("ciphertext_len" not in expected,
                f"handshake case must not carry ciphertext: {case_id}")
        if "verifier" in expected:
            if expected.get("binding_state") == "window":
                require(expected.get("verifier") == "QR_POP",
                        f"window bootstrap must use QR_POP: {case_id}")
            elif expected.get("binding_state") in {"bound", "window_bound"}:
                require(expected.get("verifier") == "LONG_TERM",
                        f"bound peer must use LONG_TERM verifier: {case_id}")
            else:
                require(False,
                        f"verifier needs a binding state: {case_id}")
    elif frame_type == 1:
        require(expected.get("stage") == "AUTHENTICATED",
                f"protected case must be AUTHENTICATED stage: {case_id}")
        ciphertext_len = expected.get("ciphertext_len")
        require(type(ciphertext_len) is int,
                f"protected case must carry ciphertext length: {case_id}")
        require(type(expected.get("counter_valid")) is bool,
                f"counter validity required: {case_id}")
        if result == "ACCEPTED":
            require(ciphertext_len > 16,
                    f"accepted ciphertext must exceed the tag: {case_id}")
        if expected.get("authorization") == "UNAUTHORIZED":
            require(result == "REJECTED",
                    f"unauthorized control must reject: {case_id}")
        if result == "ACCEPTED":
            require(session_after == "AUTHENTICATED",
                    f"accepted protected message keeps session: {case_id}")
        if expected.get("recovery_query") is True:
            require(channel == "session",
                    f"recovery query is session-channel only: {case_id}")
            require(expected.get("binding_state") == "bound",
                    f"recovery query needs a bound record: {case_id}")
            require(session_after == "AUTHENTICATED",
                    f"recovery query keeps the session: {case_id}")
        if result == "UNSUPPORTED_OPERATION":
            require(expected.get("authorization") == "AUTHORIZED",
                    f"unsupported operation needs an authorized session: {case_id}")
            require(session_after == "AUTHENTICATED",
                    f"unsupported operation keeps the session: {case_id}")
    else:
        require(result == "REJECTED",
                f"unknown type must reject: {case_id}")
        require(session_after == "CLOSED",
                f"unknown type must close: {case_id}")


def validate_link_session_transport(root: Path) -> None:
    semantic = load_json(root, LINK_SESSION_TRANSPORT)
    require_exact_type(semantic, list, "session transport semantic fixture")
    ids = [case.get("id") for case in semantic if type(case) is dict]
    require(len(ids) == len(semantic),
            "every session transport case needs an id")
    require(len(set(ids)) == len(ids),
            "duplicate session transport case id")
    require(set(ids) == set(SESSION_TRANSPORT_SEMANTICS),
            "session transport semantic coverage mismatch")
    cases = {case["id"]: case for case in semantic}
    for case_id, expected in SESSION_TRANSPORT_SEMANTICS.items():
        require(cases[case_id] == {"id": case_id, **expected},
                f"session transport semantic mismatch: {case_id}")
        _require_session_transport_domain(
            {"id": case_id, **expected})


def validate_link_limits(root: Path) -> None:
    limits = load_json(root, LINK_LIMITS)
    require_exact_type(limits, dict, "link limits fixture")
    require(limits.get("reassembly_idle_timeout_ms") == 5000,
            "reassembly timeout mismatch")
    require(limits.get("indication_confirm_timeout_ms") == 2000,
            "indication timeout mismatch")
    require(limits.get("public_link_state_max_bytes") == 20,
            "public link state limit mismatch")
    require(limits.get("public_link_state_max_version") == 127,
            "public link state version limit mismatch")
    require(limits.get("public_link_state_valid_flags") == [0, 1, 2, 3],
            "public link state flags mismatch")
    require(str(limits.get("max_event_sequence")) == str((1 << 64) - 1),
            "event sequence limit mismatch")

    profile = load_yaml(root, LINK_PROFILE)
    timeouts = profile.get("timeouts")
    require_exact_type(timeouts, dict, "profile timeouts")
    require(timeouts.get("reassembly_idle_ms") == 5000,
            "profile reassembly timeout mismatch")
    require(timeouts.get("indication_confirm_ms") == 2000,
            "profile indication timeout mismatch")
    advertising = profile.get("advertising")
    require_exact_type(advertising, dict, "profile advertising")
    require(advertising.get("version") == 1,
            "profile advertising version mismatch")
    require(advertising.get("short_name") == "MT",
            "profile short name mismatch")
    require(advertising.get("flags") == {"bindable": 1},
            "profile advertising flags mismatch")
    require(advertising.get("service_data",
                            {}).get("discriminator_bytes") == 3,
            "profile discriminator size mismatch")
    require(advertising.get("service_data",
                            {}).get("uuid") ==
            profile["services"][0]["uuid"],
            "profile advertising UUID mismatch")
    require(limits.get("advertising") == {
        "version": 1,
        "max_payload_bytes": 31,
        "service_data_ad_type": 33,
        "service_uuid_bytes": 16,
        "discriminator_bytes": 3,
    }, "link limits advertising mismatch")
    require(limits.get("session_transport") == {
        "type_bytes": 1,
        "handshake_type": 0,
        "encrypted_type": 1,
    }, "link limits session_transport mismatch")
    require(limits.get("qr") == {
        "version": "link-v1",
        "short_name": "MT",
        "pop_bytes": 16,
        "pop_chars": 22,
        "discriminator_bytes": 3,
        "discriminator_chars": 4,
        "expires_in_ms_max": 3600000,
    }, "link limits qr mismatch")
    require(limits.get("framing") == {
        "maximum_control_message_bytes":
            profile.get("framing", {}).get("maximum_control_message_bytes"),
        "maximum_session_message_bytes":
            profile.get("framing", {}).get("maximum_session_message_bytes"),
    }, "link limits framing mismatch with profile")
    require(limits.get("framing") == {
        "maximum_control_message_bytes": 4096,
        "maximum_session_message_bytes": 1024,
    }, "link limits framing mismatch")
    session_transport = profile.get("session_transport")
    qr_profile = profile.get("qr")
    require(limits["session_transport"]["type_bytes"] ==
            session_transport["type_bytes"],
            "session_transport type size mismatch with profile")
    require(limits["session_transport"]["handshake_type"] ==
            session_transport["handshake_type"],
            "session_transport handshake type mismatch with profile")
    require(limits["session_transport"]["encrypted_type"] ==
            session_transport["encrypted_type"],
            "session_transport encrypted type mismatch with profile")
    require(limits["qr"]["pop_bytes"] == qr_profile["pop_bytes"],
            "QR pop size mismatch with profile")
    require(limits["qr"]["discriminator_bytes"] ==
            qr_profile["discriminator_bytes"],
            "QR discriminator size mismatch with profile")
    require(limits["qr"]["expires_in_ms_max"] ==
            qr_profile["expires_in_ms_max"],
            "QR expiry bound mismatch with profile")
    link_state = profile["services"][0]["characteristics"][0]
    require(link_state.get("public_wire") == "PublicLinkState",
            "profile public wire mismatch")
    require(link_state.get("public_max_bytes") == 20,
            "profile public max bytes mismatch")


def _public_state_domain_valid(message: Any, max_version: int) -> bool:
    if message.protocol_major > max_version or \
            message.protocol_minor > max_version or \
            message.profile_major > max_version or \
            message.profile_minor > max_version:
        return False
    if message.boot_id == 0:
        return False
    if message.state_flags & ~0x03 != 0:
        return False
    return True


def validate_link_public_state(
        root: Path, registry: DescriptorRegistry) -> None:
    limits = load_json(root, LINK_LIMITS)
    max_bytes = limits["public_link_state_max_bytes"]
    max_version = limits["public_link_state_max_version"]
    golden = load_json(root, LINK_GOLDEN)
    cases = [case for case in golden
             if case.get("type") == "microtech.link.v1.PublicLinkState"]
    require(bool(cases), "missing PublicLinkState golden case")
    for case in cases:
        payload = _decode_hex(case.get("hex", ""), case["id"])
        message = registry.message_class(case["type"])()
        try:
            message.ParseFromString(payload)
        except DecodeError as error:
            raise ContractValidationError(
                f"public link state did not parse: {case.get('id')}"
            ) from error
        require(message.SerializeToString(deterministic=True) == payload,
                f"public link state is not canonical: {case.get('id')}")
        require(len(payload) <= max_bytes,
                f"public link state exceeds {max_bytes} bytes: {case.get('id')}")
        require(_public_state_domain_valid(message, max_version),
                f"public link state violates value domain: {case.get('id')}")

    for flags in limits["public_link_state_valid_flags"]:
        message = registry.message_class(
            "microtech.link.v1.PublicLinkState")()
        message.protocol_major = max_version
        message.protocol_minor = max_version
        message.profile_major = max_version
        message.profile_minor = max_version
        message.boot_id = (1 << 64) - 1
        message.state_flags = flags
        encoded = message.SerializeToString(deterministic=True)
        require(len(encoded) <= max_bytes,
                f"legal public link state flags {flags} exceed limit")

    invalid = registry.message_class("microtech.link.v1.PublicLinkState")()
    invalid.protocol_major = max_version + 1
    invalid.boot_id = 1
    require(not _public_state_domain_valid(invalid, max_version),
            "public link state version domain not enforced")
    invalid.protocol_major = 1
    invalid.boot_id = 0
    require(not _public_state_domain_valid(invalid, max_version),
            "public link state boot domain not enforced")
    invalid.protocol_major = 1
    invalid.boot_id = 1
    invalid.state_flags = 4
    require(not _public_state_domain_valid(invalid, max_version),
            "public link state flag domain not enforced")


def validate_device_link(root: Path, registry: DescriptorRegistry) -> None:
    validate_link_profile(root)
    validate_link_framing(root)
    validate_link_security_semantics(root)
    validate_link_session_transport(root)
    validate_link_protobuf(root, registry)
    validate_link_advertising(root)
    validate_link_qr(root)
    validate_link_limits(root)
    validate_link_public_state(root, registry)
