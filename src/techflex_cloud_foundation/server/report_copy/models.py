from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
import re
from typing import Any, Literal
from uuid import UUID

from techflex_cloud_foundation.platform_errors import RequestContractError


@dataclass(frozen=True, slots=True)
class LocalBasicCopyRequest:
    session_id: UUID
    report_id: str
    version: int
    source: Literal["LOCAL_BASIC_COPY"]
    document_json: str
    pdf_bytes: bytes
    document_sha256: str
    pdf_sha256: str
    consent_record_id: UUID


@dataclass(frozen=True, slots=True)
class LocalBasicCopyReceipt:
    report_id: str
    version: int
    document_sha256: str
    pdf_sha256: str


@dataclass(frozen=True, slots=True)
class LocalBasicCopyRecord:
    tenant_id: UUID
    session_id: UUID
    report_id: str
    version: int
    source: Literal["LOCAL_BASIC_COPY"]
    document_json: str
    document_sha256: str
    pdf_sha256: str
    pdf_object_key: str
    pdf_size_bytes: int


def validate_local_basic_copy(request: LocalBasicCopyRequest) -> LocalBasicCopyRequest:
    if not isinstance(request.report_id, str) or not re.fullmatch(
        r"[A-Za-z0-9-]{1,64}", request.report_id
    ):
        raise RequestContractError("invalid report ID")
    if (
        type(request.version) is not int
        or request.version != 1
        or request.source != "LOCAL_BASIC_COPY"
    ):
        raise RequestContractError("unsupported report copy version or source")
    if not isinstance(request.document_json, str) or not isinstance(request.pdf_bytes, bytes):
        raise RequestContractError("invalid report copy payload type")
    document_bytes = request.document_json.encode("utf-8")
    if len(document_bytes) > 1024 * 1024:
        raise RequestContractError("report document exceeds size limit")
    if len(request.pdf_bytes) > 8 * 1024 * 1024:
        raise RequestContractError("report PDF exceeds size limit")
    if not request.pdf_bytes.startswith(b"%PDF-") or b"%%EOF" not in request.pdf_bytes[-1024:]:
        raise RequestContractError("invalid report PDF")
    if hashlib.sha256(document_bytes).hexdigest() != request.document_sha256:
        raise RequestContractError("report document digest mismatch")
    if hashlib.sha256(request.pdf_bytes).hexdigest() != request.pdf_sha256:
        raise RequestContractError("report PDF digest mismatch")
    try:
        document = json.loads(request.document_json)
        if not isinstance(document, dict):
            raise TypeError("document")
        for name in (
            "report_id",
            "status",
            "kind",
            "session_id",
            "analysis_result_id",
            "subject_display_id",
            "protocol_id",
            "protocol_version",
            "summary",
            "disclaimer",
        ):
            if not isinstance(document[name], str):
                raise TypeError(name)
        for name in ("captured_at", "generated_at"):
            datetime.fromisoformat(document[name])
        if not isinstance(document["metrics"], list) or not isinstance(
            document["relative_heatmap"], list
        ):
            raise TypeError("metrics or heatmap")
        if not isinstance(document["provenance"], list) or not all(
            isinstance(item, str) for item in document["provenance"]
        ):
            raise TypeError("provenance")
        for metric in document["metrics"]:
            _validate_metric(metric)
        _validate_heatmap(document["relative_heatmap"])
        for stage in document.get("stages", []):
            if not isinstance(stage["stage_id"], str) or not isinstance(stage["title"], str):
                raise TypeError("stage")
            _validate_heatmap(stage["relative_heatmap"])
            for metric in stage["metrics"]:
                _validate_metric(metric)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise RequestContractError("invalid local basic report document") from exc
    if document["report_id"] != request.report_id:
        raise RequestContractError("report ID binding mismatch")
    if (
        type(document["version"]) is not int
        or document["version"] != 1
        or document["status"] != "BASIC_READY"
        or document["kind"] != "BASIC"
    ):
        raise RequestContractError("unsupported report status or kind")
    try:
        document_session_id = UUID(document["session_id"])
    except ValueError as exc:
        raise RequestContractError("invalid report session ID") from exc
    if document_session_id != request.session_id:
        raise RequestContractError("report session binding mismatch")
    return request


def _validate_metric(metric: dict[str, Any]) -> None:
    if not isinstance(metric, dict):
        raise TypeError("metric")
    for key in ("key", "label", "unit", "definition_version"):
        if not isinstance(metric[key], str):
            raise TypeError("metric field")
    value = metric["value"]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("metric value")


def _validate_heatmap(rows: list[Any]) -> None:
    for row in rows:
        if not isinstance(row, list):
            raise TypeError("heatmap row")
        for value in row:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError("heatmap value")
