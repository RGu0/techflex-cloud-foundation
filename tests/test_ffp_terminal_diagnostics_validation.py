"""RAY-802 whitelist and identity screen, against the client's Redactor rules."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest

from techflex_cloud_foundation.server.terminal_diagnostics.validation import (
    DiagnosticRejection,
    contains_identity,
    is_sensitive_key,
    validate_package,
)

FIXTURE = Path(__file__).parent / "fixtures" / "ffp_terminal_diagnostics" / "ray910_export.ndjson"
TENANT = UUID("5a1f0c3e-7b2d-4e8a-9c6f-2d4b8e1a0f37")
TERMINAL = UUID("c3d9e2f1-6a4b-4f0c-8e7d-9b2a1c0d3e5f")
HEADER = {
    "kind": "header", "exported_at": "2026-10-29T06:51:33.000Z", "app_version": None,
    "cloud_environment": None, "platform": "ios", "os_version": "18.1",
    "terminal_id": str(TERMINAL), "tenant_id": str(TENANT),
    "format": "gait-insole-diagnostics/1", "dropped_lines": 0,
}


def _body(*records) -> bytes:
    return "".join(
        (record if isinstance(record, str) else json.dumps(record, ensure_ascii=False)) + "\n"
        for record in records
    ).encode("utf-8")


def _log(**fields) -> dict:
    return {"kind": "log", "t": "2026-10-29T06:40:00.000Z", "level": "info", "cat": "app",
            "msg": "ok", **fields}


def _reject(payload: bytes) -> tuple[int, str]:
    with pytest.raises(DiagnosticRejection) as raised:
        validate_package(payload, tenant_id=TENANT, client_installation_id=TERMINAL)
    return raised.value.line, raised.value.reason.value


def test_real_ray910_export_is_accepted() -> None:
    payload = FIXTURE.read_bytes()
    assert validate_package(payload, tenant_id=TENANT, client_installation_id=TERMINAL) == 8
    # The fixture really went through the client's redaction.
    text = payload.decode("utf-8")
    for leaked in ("王芳", "Li Wei", "A-0042", "13900001111", "li.wei@example.com"):
        assert leaked not in text
    assert '"<redacted:phone>":{"attempts":2}' in text


@pytest.mark.parametrize(("line", "old", "new"), [
    (6, '"notify timeout"', '"notify timeout 13912345678"'),
    (6, '"notify timeout"', '"notify timeout １３９１２３４５６７８"'),
    (2, '"telemetry":true', '"patientName":"Wang Fang"'),
    (2, '"telemetry":true', '"institution_no":"A-0042"'),
    (4, '"subject_name":"<redacted>"', '"subject_name":"王芳"'),
    (4, '"contactTel":"<redacted>"', '"contactTel":{"v":"<redacted>"}'),
    (5, '"<redacted:phone>":{', '"13912345678":{'),
    (5, '"note":"<redacted> asked', '"note":"wf@example.org asked'),
    (8, '"params":"hz=100"', '"params":"id 11010519491231002X"'),
])
def test_planted_identity_in_a_copy_of_the_export_is_rejected(line, old, new) -> None:
    lines = FIXTURE.read_text("utf-8").splitlines(keepends=True)
    assert old in lines[line - 1]
    lines[line - 1] = lines[line - 1].replace(old, new)
    assert _reject("".join(lines).encode("utf-8")) == (line, "identity_detected")


def test_each_rejection_reason_names_the_first_failing_line() -> None:
    header = dict(HEADER)
    assert _reject(b"") == (1, "header_missing")
    assert _reject(_body(header, "{not json")) == (2, "not_json")
    assert _reject(_body(header, "[1, 2]")) == (2, "not_json")
    assert _reject(_body(header, '{"kind":"log","t":NaN}')) == (2, "not_json")
    assert _reject(_body(header, '{"kind":"log","kind":"log"}')) == (2, "not_json")
    assert _reject(_body(header, "")) == (2, "not_json")
    assert _reject(b'{"kind":"header"}\xff\n') == (1, "not_json")
    assert _reject(_body(header, "[" * 100_000 + "]" * 100_000)) == (2, "not_json")
    assert _reject(_body(_log(), header)) == (1, "header_missing")
    assert _reject(_body({**header, "format": "gait-insole-diagnostics/2"})) == (
        1, "format_unsupported")
    assert _reject(_body({**header, "format": None})) == (1, "format_unsupported")
    assert _reject(_body(header, {"kind": "audit"})) == (2, "unknown_kind")
    assert _reject(_body(header, {"t": "x"})) == (2, "unknown_kind")
    assert _reject(_body(header, header)) == (2, "unknown_kind")
    assert _reject(_body({**header, "subject": "x"})) == (1, "unknown_field")
    assert _reject(_body(header, _log(timeline=[]))) == (2, "unknown_field")
    assert _reject(_body(header, {"kind": "command", "t": "x", "msg": "x"})) == (
        2, "unknown_field")
    assert _reject(_body({**header, "tenant_id": str(TERMINAL)})) == (1, "header_mismatch")
    assert _reject(_body({**header, "terminal_id": None})) == (1, "header_mismatch")
    assert _reject(_body({**header, "terminal_id": "not-a-uuid"})) == (1, "header_mismatch")
    assert _reject(_body(header, _log(), _log(msg="138-1234-5678"))) == (3, "identity_detected")


def test_header_ids_compare_as_uuids_and_minimal_lines_pass() -> None:
    header = {**HEADER, "tenant_id": str(TENANT).upper()}
    command = {"kind": "command", "t": "x", "command": "C", "params": "", "elapsed_ms": 1}
    payload = _body(header, _log(), command).rstrip(b"\n")
    assert validate_package(payload, tenant_id=TENANT, client_installation_id=TERMINAL) == 3


@pytest.mark.parametrize("key", [
    "name", "subject_name", "patientName", "institutionNo", "INSTITUTION-NO",
    "home_tel", "contactTel", "doctor_name", "ship_address", "bossName",
    "contact_device_name", "tel_ip_address", "email", "birthday", "姓名", "机构编号",
    "name#2", "contact <redacted:phone>",
])
def test_identity_keys_match_the_client(key) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", [
    "subject_uuid", "device_name", "left_mac_address", "leftMacAddress", "ip_address",
    "firmware_name", "telemetry", "hotelling", "rssi", "frame", "app_version",
    # Keys the client redacted as text: the placeholder is not a fragment.
    "<redacted:phone>", "<redacted:email>", "<redacted:phone>#2", "<redacted>", "<redacted:id>",
])
def test_device_and_placeholder_keys_are_not_identity(key) -> None:
    assert not is_sensitive_key(key)


@pytest.mark.parametrize("text", [
    "13812345678", "+86 138 1234 5678", "86-138-1234-5678", "１３８１２３４５６７８",
    "010-12345678", "(010)12345678", "0755-1234-5678", "a@b.cn", "li＠example．com",
    "11010519491231002X", "110105194912310021",
])
def test_identity_patterns(text) -> None:
    assert contains_identity(text)


@pytest.mark.parametrize("text", [
    "0102 3040 5060", "0755 1234 5678", "a13812345678", "138123456789",
    "C0:FF:EE:00:00:01", "8d0b9c1e-5f2a-4c4e-9b8a-0d6f3e2a1b7c", "<redacted:phone>",
    "1101051949123100211", "BAT 3987", "TimeoutException after 0:00:05.000000",
])
def test_device_data_is_not_identity(text) -> None:
    assert not contains_identity(text)


def test_sensitive_key_value_must_be_exactly_the_placeholder_at_any_depth() -> None:
    def outcome(fields):
        try:
            validate_package(_body(HEADER, _log(fields=fields)), tenant_id=TENANT,
                             client_installation_id=TERMINAL)
        except DiagnosticRejection as rejection:
            return rejection.reason.value
        return "accepted"

    assert outcome({"a": [{"b": {"subject_name": "<redacted>"}}]}) == "accepted"
    assert outcome({"a": [{"b": {"subject_name": None}}]}) == "identity_detected"
    assert outcome({"a": [{"b": {"subject_name": ""}}]}) == "identity_detected"
    assert outcome({"a": [{"b": {"subject_name": "<redacted:phone>"}}]}) == "identity_detected"
    assert outcome({"x": ["ok", ["deep", {"note": "13812345678"}]]}) == "identity_detected"
    # Numbers are not text; the client leaves them unchanged as well.
    assert outcome({"count": 13812345678}) == "accepted"
    nested: dict = {}
    cursor = nested
    for _ in range(500):
        cursor["n"] = {}
        cursor = cursor["n"]
    cursor["home_tel"] = "x"
    assert outcome(nested) == "identity_detected"


# Built inside the test: as parameters, the 8 MiB strings became test ids.
_FULL_SIZE = {
    "letters": lambda: "a" * (8 * 1024 * 1024 - 1024),
    "at_then_letters": lambda: "a@" + "a" * (8 * 1024 * 1024 - 1024),
    "local_part_symbols": lambda: ".-" * (4 * 1024 * 1024 - 1024),
}


@pytest.mark.parametrize("shape", sorted(_FULL_SIZE))
def test_screen_stays_linear_on_a_full_size_string(shape) -> None:
    import time

    text = _FULL_SIZE[shape]()
    # A quadratic pattern takes hours here (review of 9dd3ff7, finding 1).
    payload = _body(HEADER, _log(msg=text))
    started = time.perf_counter()
    validate_package(payload, tenant_id=TENANT, client_installation_id=TERMINAL)
    assert time.perf_counter() - started < 20


def test_a_placeholder_cannot_hide_an_identity_key() -> None:
    assert is_sensitive_key("na<redacted>me")
    assert is_sensitive_key("con<redacted:id>tact")
    assert _reject(_body(HEADER, _log(fields={"na<redacted>me": "Wang Fang"}))) == (
        2, "identity_detected")


def test_header_ids_shaped_like_a_landline_are_accepted() -> None:
    # Review of 3d98f21: digit-only middle groups match the landline pattern.
    tenant = UUID("5a1f0c3e-0123-4567-8901-2d4b8e1a0f37")
    terminal = UUID("c3d9e2f1-0755-1234-5678-9b2a1c0d3e5f")
    assert contains_identity(str(tenant)) and contains_identity(str(terminal))
    header = {**HEADER, "tenant_id": str(tenant), "terminal_id": str(terminal)}
    assert validate_package(
        _body(header, _log()), tenant_id=tenant, client_installation_id=terminal) == 2
    # Elsewhere the same text is still screened.
    with pytest.raises(DiagnosticRejection) as raised:
        validate_package(_body(header, _log(msg=str(tenant))), tenant_id=tenant,
                         client_installation_id=terminal)
    assert (raised.value.line, raised.value.reason.value) == (2, "identity_detected")
