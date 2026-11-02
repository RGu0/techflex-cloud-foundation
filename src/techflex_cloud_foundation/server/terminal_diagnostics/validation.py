"""Whole-package whitelist check of a ``gait-insole-diagnostics/1`` upload.

Pure: no I/O. The first failing line rejects the whole package; the error
names that line and a fixed reason, never the content.

The identity screen ports the client's ``Redactor`` (gait-insole-flutter
``packages/app_common/lib/src/redactor.dart``, RAY-910) so that everything a
correct client export holds passes, and an identity value the export missed
does not:

* Keys. A key that looks like identity data (normalised fragments, the
  ``tel`` suffix, the allowed-key token rule) may only hold ``<redacted>``,
  at any depth. The client checks the key before redacting it as text; here
  only the redacted key is visible, so the placeholders it may contain are
  neutralised first (``<redacted:phone>`` must not read as a ``phone`` key).
* Patterns. No string, key or value, may still hold a mobile, landline,
  e-mail or resident ID number after full-width normalisation. The client
  applies its patterns one after another, so ``a@b.cn13812345678`` exports
  as ``<redacted:email>13812345678``; that number is rejected here, on
  purpose. Numbers are not text and are not screened, as in the client.

Registered values (the names the client held at export) cannot be known
here; that layer stays the client's.
"""

from __future__ import annotations

import json
import re
from typing import Any
from uuid import UUID

from techflex_cloud_foundation.contracts.terminal_diagnostics import (
    DIAGNOSTICS_FORMAT,
    DIAGNOSTICS_LINE_FIELDS,
    DIAGNOSTICS_REDACTED_VALUE,
)
from techflex_cloud_foundation.contracts.terminal_diagnostics import (
    DiagnosticRejectionReason as Reason,
)

# Redactor.defaultSensitiveKeyFragments.
SENSITIVE_KEY_FRAGMENTS = (
    "name", "phone", "mobile", "telephone", "contact", "email", "mail", "address",
    "wechat", "idcard", "idnumber", "identity", "institutionnumber", "institutionid",
    "institutionno", "instno", "externalid", "recordno", "recordnumber",
    "medicalrecord", "birth", "姓名", "电话", "手机", "地址", "邮箱", "微信", "联系",
    "身份证", "档案号", "病历号", "住院号", "机构号", "机构编号",
)

# Redactor.defaultAllowedKeys: device, software and app keys, never a person.
ALLOWED_KEYS = (
    "subject_uuid", "installation_label", "device_name", "device_identity",
    "device_address", "mac_address", "ble_address", "ip_address", "service_name",
    "characteristic_name", "host_name", "firmware_name", "file_name", "package_name",
    "app_name", "os_name", "platform_name", "protocol_name", "template_name",
    "event_name", "category_name",
)

_TEL_SUFFIX = "tel"
_KEY_SEPARATORS = re.compile(r"[\s_\-]")
_TOKEN_SEPARATORS = re.compile(r"[\s_\-]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
# Every placeholder the client writes into text. Replaced by a character the
# key normalisation keeps, so two halves cannot join into a fragment.
_PLACEHOLDERS = re.compile(r"<redacted(?::(?:id|phone|email))?>")

# Redactor._patterns, in one expression. Dart's \d is ASCII-only.
_IDENTITY_PATTERN = re.compile(
    "|".join((
        # Mainland resident ID: 17 digits + check digit.
        r"(?<![0-9])[0-9]{17}[0-9Xx](?![0-9Xx])",
        # Mainland mobile numbers, optionally with +86 / 86 and separators.
        r"(?<![A-Za-z0-9])(?:\+?86[ -]?)?1[3-9][0-9][ -]?[0-9]{4}[ -]?[0-9]{4}(?![0-9])",
        # Landlines with a dash or parentheses after the area code.
        r"(?<![A-Za-z0-9])(?:\(0[0-9]{2,3}\)\s?|0[0-9]{2,3}-)[0-9]{3,4}-?[0-9]{4}(?![0-9])",
        # The client's parts are unbounded. Any match it finds has a local
        # suffix of at most 64 characters that matches too; the domain bound
        # misses only names longer than DNS allows (253). The bounds keep a
        # long run with or without "@" linear instead of quadratic.
        r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}",
    ))
)
# Full-width digits and ＋ － ． ＠ to ASCII, as Redactor._normalizeWidth.
_WIDTH = {code: code - 0xFEE0 for code in (*range(0xFF10, 0xFF1A), 0xFF0B, 0xFF0D, 0xFF0E, 0xFF20)}


_HEADER_IDS = frozenset({"tenant_id", "terminal_id"})


class DiagnosticRejection(Exception):
    def __init__(self, line: int, reason: Reason) -> None:
        super().__init__(f"line {line}: {reason.value}")
        self.line = line
        self.reason = reason


def _normalize_key(key: str) -> str:
    return _KEY_SEPARATORS.sub("", key.lower())


_FRAGMENTS = tuple(_normalize_key(fragment) for fragment in SENSITIVE_KEY_FRAGMENTS)


def _tokens(key: str) -> list[str]:
    return [
        word.lower()
        for part in _TOKEN_SEPARATORS.split(key)
        for word in _CAMEL_BOUNDARY.split(part)
        if word
    ]


_ALLOWED_TOKENS = tuple(_tokens(key) for key in ALLOWED_KEYS)


def _is_allowed_key(key: str) -> bool:
    tokens = _tokens(key)
    for allowed in _ALLOWED_TOKENS:
        if not allowed or len(allowed) > len(tokens):
            continue
        start = len(tokens) - len(allowed)
        if tokens[start:] != allowed:
            continue
        prefix = "".join(tokens[:start])
        if not any(fragment in prefix for fragment in _FRAGMENTS) and not prefix.endswith(
            _TEL_SUFFIX
        ):
            return True
    return False


def _client_sensitive(key: str) -> bool:
    if _is_allowed_key(key):
        return False
    normalized = _normalize_key(key)
    return normalized.endswith(_TEL_SUFFIX) or any(
        fragment in normalized for fragment in _FRAGMENTS
    )


def is_sensitive_key(key: str) -> bool:
    """Redactor.isSensitiveKey, applied to a key as the export wrote it.

    Checked with the placeholders replaced by a separator (so
    ``<redacted:phone>`` is not a ``phone`` key) and removed (so
    ``na<redacted>me`` cannot hide a ``name`` key).
    """

    return _client_sensitive(_PLACEHOLDERS.sub("/", key)) or _client_sensitive(
        _PLACEHOLDERS.sub("", key)
    )


def contains_identity(text: str) -> bool:
    return _IDENTITY_PATTERN.search(text.translate(_WIDTH)) is not None


def _screen(value: Any) -> bool:
    """True when ``value`` holds identity data anywhere; iterative, any depth."""

    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if contains_identity(item):
                return True
        elif isinstance(item, dict):
            for key, child in item.items():
                if contains_identity(key):
                    return True
                if is_sensitive_key(key):
                    if child != DIAGNOSTICS_REDACTED_VALUE:
                        return True
                else:
                    pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
    return False


def _reject_constant(_name: str) -> Any:
    raise ValueError("NaN and Infinity are not JSON")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate key")
    return result


def _parse(raw: bytes, line: int) -> dict[str, Any]:
    try:
        record = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise DiagnosticRejection(line, Reason.NOT_JSON) from None
    if not isinstance(record, dict):
        raise DiagnosticRejection(line, Reason.NOT_JSON)
    return record


def _same_id(value: Any, expected: UUID) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return UUID(value) == expected
    except ValueError:
        return False


def validate_package(
    payload: bytes, *, tenant_id: UUID, client_installation_id: UUID
) -> int:
    """Return the number of lines, or raise ``DiagnosticRejection``.

    ``\\n`` ends a line, as the client writes it; the final one may end the
    payload. A blank line anywhere else is not JSON.
    """

    lines = payload.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        raise DiagnosticRejection(1, Reason.HEADER_MISSING)
    for number, raw in enumerate(lines, start=1):
        record = _parse(raw, number)
        kind = record.get("kind")
        if number == 1:
            if kind != "header":
                raise DiagnosticRejection(number, Reason.HEADER_MISSING)
            if record.get("format") != DIAGNOSTICS_FORMAT:
                raise DiagnosticRejection(number, Reason.FORMAT_UNSUPPORTED)
        elif kind == "header" or not isinstance(kind, str) or kind not in DIAGNOSTICS_LINE_FIELDS:
            # Exactly one header, and it comes first.
            raise DiagnosticRejection(number, Reason.UNKNOWN_KIND)
        if not record.keys() <= DIAGNOSTICS_LINE_FIELDS[kind]:
            raise DiagnosticRejection(number, Reason.UNKNOWN_FIELD)
        if number == 1 and not (
            _same_id(record.get("tenant_id"), tenant_id)
            and _same_id(record.get("terminal_id"), client_installation_id)
        ):
            raise DiagnosticRejection(number, Reason.HEADER_MISMATCH)
        # The header ids equal the authenticated ids exactly; a UUID can look
        # like a landline ("…-0123-4567-8901-…") and must not be screened.
        screened = (
            value for key, value in record.items()
            if number != 1 or key not in _HEADER_IDS
        )
        if any(_screen(value) for value in screened):
            raise DiagnosticRejection(number, Reason.IDENTITY_DETECTED)
    return len(lines)


__all__ = [
    "ALLOWED_KEYS",
    "DiagnosticRejection",
    "SENSITIVE_KEY_FRAGMENTS",
    "contains_identity",
    "is_sensitive_key",
    "validate_package",
]
