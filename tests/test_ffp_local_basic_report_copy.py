"""RAY-99 R10 report-copy contract tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import importlib
import json
from uuid import uuid4

import pytest

from techflex_cloud_foundation.platform_errors import RequestContractError


def copy_request(*, report_id: str = "basic-123abc", pdf: bytes = b"%PDF-1.4\n%%EOF"):
    session_id = uuid4()
    # The document is written as the ffp client serialises it: sorted keys, compact separators.
    document_json = json.dumps(
        {
            "report_id": report_id, "version": 1, "status": "BASIC_READY", "kind": "BASIC",
            "session_id": str(session_id), "analysis_result_id": "analysis-1",
            "subject_display_id": "masked-test",
            "captured_at": datetime.now(UTC).isoformat(),
            "generated_at": datetime.now(UTC).isoformat(),
            "protocol_id": "standard-static-balance", "protocol_version": "1",
            "metrics": [{
                "key": "left_load_percent", "label": "left", "value": 50.0,
                "unit": "percent", "definition_version": "1",
            }],
            "relative_heatmap": [[0.5]], "summary": "synthetic test",
            "disclaimer": "internal synthetic", "provenance": ["local-basic/1.0.0"],
            "stages": [],
        },
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    models = importlib.import_module("techflex_cloud_foundation.server.report_copy.models")
    return models.LocalBasicCopyRequest(
        session_id=session_id, report_id=report_id, version=1,
        source="LOCAL_BASIC_COPY", document_json=document_json, pdf_bytes=pdf,
        document_sha256=hashlib.sha256(document_json.encode()).hexdigest(),
        pdf_sha256=hashlib.sha256(pdf).hexdigest(), consent_record_id=uuid4(),
    )


def test_accepts_valid_local_basic_copy_contract() -> None:
    models = importlib.import_module("techflex_cloud_foundation.server.report_copy.models")
    request = copy_request()
    # A report must bind to the exact uploaded session; no inferred remapping.
    invalid = replace(request, session_id=uuid4())
    with pytest.raises(RequestContractError, match="session"):
        models.validate_local_basic_copy(invalid)
    assert models.validate_local_basic_copy(request) is request


def test_accepts_local_hex_spelling_of_the_same_session_uuid() -> None:
    models = importlib.import_module("techflex_cloud_foundation.server.report_copy.models")
    request = copy_request()
    document = json.loads(request.document_json)
    document["session_id"] = request.session_id.hex
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    equivalent = replace(
        request, document_json=payload,
        document_sha256=hashlib.sha256(payload.encode()).hexdigest(),
    )
    assert models.validate_local_basic_copy(equivalent) is equivalent


@pytest.mark.parametrize("report_id", ["../escape", "bad_name", "", "x" * 65, "含中文"])
def test_rejects_unsafe_report_id(report_id: str) -> None:
    models = importlib.import_module("techflex_cloud_foundation.server.report_copy.models")
    with pytest.raises(RequestContractError, match="report ID"):
        models.validate_local_basic_copy(replace(copy_request(), report_id=report_id))


@pytest.mark.parametrize("changes", [
    {"version": 2}, {"source": "CLOUD_COMPLETE"},
    {"document_sha256": "0" * 64}, {"pdf_sha256": "0" * 64},
    {"pdf_bytes": b"not a PDF"}, {"pdf_bytes": b"%PDF-1.4\n" + b"x" * (8 * 1024 * 1024)},
])
def test_rejects_invalid_copy_metadata(changes: dict) -> None:
    models = importlib.import_module("techflex_cloud_foundation.server.report_copy.models")
    with pytest.raises(RequestContractError):
        models.validate_local_basic_copy(replace(copy_request(), **changes))


def test_rejects_wrong_document_status_and_oversize_document() -> None:
    models = importlib.import_module("techflex_cloud_foundation.server.report_copy.models")
    request = copy_request()
    value = json.loads(request.document_json)
    value["status"] = "FULL_READY"
    wrong_status = json.dumps(value)
    with pytest.raises(RequestContractError, match="status"):
        models.validate_local_basic_copy(replace(
            request, document_json=wrong_status,
            document_sha256=hashlib.sha256(wrong_status.encode()).hexdigest(),
        ))
    oversized = request.document_json + " " * (1024 * 1024)
    with pytest.raises(RequestContractError, match="size"):
        models.validate_local_basic_copy(replace(request, document_json=oversized))
