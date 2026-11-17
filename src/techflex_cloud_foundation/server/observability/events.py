from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
import json
import re
from typing import Any


class Severity(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


_SAFE_CONTEXT_KEYS = {
    "operation",
    "status",
    "retryable",
    "attempt_count",
    "duration_ms",
    "http_status",
    "pending_sessions",
    "pending_bytes",
    "disk_free_bytes",
    "offline_seconds",
    "queue_depth",
    "manifest_status",
    "artifact_kind",
    "device_state",
    "component_version",
    "crash_type",
    "reason_code",
}
_FORBIDDEN_KEY_PARTS = {
    "name",
    "phone",
    "email",
    "external_id",
    "identity",
    "id_card",
    "token",
    "password",
    "secret",
    "raw",
    "payload",
    "report_content",
    "stack",
    "traceback",
}
_SECRET_VALUE = re.compile(r"(?i)(bearer\s+\S+|token\s*[=:]|password\s*[=:]|secret\s*[=:])")


def _validate_value(value: Any) -> None:
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if _SECRET_VALUE.search(value):
            raise ValueError("safe context contains a secret-like value")
        return
    if isinstance(value, dict):
        validate_safe_mapping(value)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_value(item)
        return
    raise ValueError("safe context only accepts JSON scalar and container values")


def validate_safe_mapping(value: dict[str, Any]) -> None:
    for key, item in value.items():
        normalized = key.lower()
        if key not in _SAFE_CONTEXT_KEYS or any(
            forbidden in normalized for forbidden in _FORBIDDEN_KEY_PARTS
        ):
            raise ValueError(f"safe context key is not allowlisted: {key}")
        _validate_value(item)


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    timestamp: datetime
    severity: Severity
    component: str
    event_name: str
    tenant_id: str
    site_id: str | None
    terminal_id: str | None
    device_id: str | None
    session_id: str | None
    segment_index: int | None
    upload_task_id: str | None
    analysis_run_id: str | None
    report_id: str | None
    correlation_id: str
    app_version: str | None
    config_version: str | None
    error_code: str | None
    safe_context_json: str

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "component": self.component,
            "event_name": self.event_name,
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "terminal_id": self.terminal_id,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "segment_index": self.segment_index,
            "upload_task_id": self.upload_task_id,
            "analysis_run_id": self.analysis_run_id,
            "report_id": self.report_id,
            "correlation_id": self.correlation_id,
            "app_version": self.app_version,
            "config_version": self.config_version,
            "error_code": self.error_code,
            "safe_context": json.loads(self.safe_context_json),
        }


def build_event(
    *,
    timestamp: datetime,
    severity: Severity,
    component: str,
    event_name: str,
    tenant_id: str,
    correlation_id: str,
    safe_context: dict[str, Any],
    site_id: str | None = None,
    terminal_id: str | None = None,
    device_id: str | None = None,
    session_id: str | None = None,
    segment_index: int | None = None,
    upload_task_id: str | None = None,
    analysis_run_id: str | None = None,
    report_id: str | None = None,
    app_version: str | None = None,
    config_version: str | None = None,
    error_code: str | None = None,
) -> TelemetryEvent:
    validate_safe_mapping(safe_context)
    return TelemetryEvent(
        timestamp=timestamp,
        severity=severity,
        component=component,
        event_name=event_name,
        tenant_id=tenant_id,
        site_id=site_id,
        terminal_id=terminal_id,
        device_id=device_id,
        session_id=session_id,
        segment_index=segment_index,
        upload_task_id=upload_task_id,
        analysis_run_id=analysis_run_id,
        report_id=report_id,
        correlation_id=correlation_id,
        app_version=app_version,
        config_version=config_version,
        error_code=error_code,
        safe_context_json=json.dumps(
            safe_context,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def analysis_failure_event(
    *,
    tenant_id: str,
    session_id: str,
    analysis_run_id: str,
    correlation_id: str,
    error_code: str,
    retryable: bool,
    exception: Exception,
) -> TelemetryEvent:
    del exception
    return build_event(
        timestamp=datetime.now(UTC),
        severity=Severity.ERROR,
        component="cloud.analysis",
        event_name="analysis_failed",
        tenant_id=tenant_id,
        session_id=session_id,
        analysis_run_id=analysis_run_id,
        correlation_id=correlation_id,
        error_code=error_code,
        safe_context={"status": "FAILED", "retryable": retryable},
    )


@dataclass(frozen=True, slots=True)
class CustomerErrorMessage:
    error_code: str
    message: str
    action: str


CUSTOMER_ERROR_ACTIONS = {
    "E-ALG-500": "系统正在自动重试；基础报告仍可使用。如持续失败，请联系支持。",
    "E-RPT-500": "请稍后重试报告生成；如持续失败，请联系支持并提供错误编号。",
    "E-CLD-409": "数据同步需要支持处理；请勿重复检测，联系支持并提供错误编号。",
}


def customer_error_message(error_code: str) -> CustomerErrorMessage:
    action = CUSTOMER_ERROR_ACTIONS.get(
        error_code,
        "请稍后重试；如问题持续，请联系支持并提供错误编号。",
    )
    return CustomerErrorMessage(
        error_code=error_code,
        message="当前操作暂未完成。",
        action=action,
    )


REQUIRED_SLI_NAMES = frozenset(
    {
        "acquisition_completion_seconds",
        "segment_verification_failures",
        "upload_backlog_sessions",
        "upload_backlog_bytes",
        "terminal_offline_seconds",
        "manifest_conflicts",
        "analysis_queue_seconds",
        "analysis_failures",
        "report_generation_seconds",
        "report_failures",
        "error_rate",
    }
)


@dataclass(frozen=True, slots=True)
class SLISample:
    metric_name: str
    value: float
    observed_at: datetime
    tenant_id: str
    terminal_id: str | None = None

    def __post_init__(self) -> None:
        if self.metric_name not in REQUIRED_SLI_NAMES:
            raise ValueError(f"unknown SLI: {self.metric_name}")
