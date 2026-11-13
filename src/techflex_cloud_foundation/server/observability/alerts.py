from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
import operator
import uuid

from techflex_cloud_foundation.server.observability.events import SLISample


class AlertSeverity(StrEnum):
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


@dataclass(frozen=True, slots=True)
class AlertRule:
    rule_id: str
    metric_name: str
    comparator: str
    threshold: float
    consecutive_samples: int
    severity: AlertSeverity
    cooldown: timedelta
    runbook: str


@dataclass(frozen=True, slots=True)
class AlertIncident:
    incident_id: str
    rule_id: str
    tenant_id: str
    terminal_id: str | None
    severity: AlertSeverity
    status: AlertStatus
    opened_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    occurrence_count: int
    runbook: str


_COMPARATORS = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
}


def default_alert_rules() -> tuple[AlertRule, ...]:
    return (
        AlertRule(
            "ops-error-rate",
            "error_rate",
            ">=",
            0.05,
            3,
            AlertSeverity.WARNING,
            timedelta(minutes=15),
            "runbooks/error-rate.md",
        ),
        AlertRule(
            "ops-upload-backlog",
            "upload_backlog_sessions",
            ">=",
            50,
            2,
            AlertSeverity.CRITICAL,
            timedelta(minutes=30),
            "runbooks/upload-backlog.md",
        ),
        AlertRule(
            "ops-terminal-offline",
            "terminal_offline_seconds",
            ">=",
            86400,
            1,
            AlertSeverity.CRITICAL,
            timedelta(hours=6),
            "runbooks/terminal-offline.md",
        ),
        AlertRule(
            "ops-manifest-conflict",
            "manifest_conflicts",
            ">=",
            1,
            1,
            AlertSeverity.CRITICAL,
            timedelta(minutes=30),
            "runbooks/manifest-conflict.md",
        ),
        AlertRule(
            "ops-analysis-failures",
            "analysis_failures",
            ">=",
            1,
            3,
            AlertSeverity.WARNING,
            timedelta(minutes=15),
            "runbooks/analysis-failure.md",
        ),
    )


class AlertEvaluator:
    def __init__(self, rules: tuple[AlertRule, ...]) -> None:
        self.rules = rules
        self._history: dict[tuple[str, str, str | None], list[SLISample]] = {}
        self._incidents: dict[tuple[str, str, str | None], AlertIncident] = {}

    def observe(self, sample: SLISample) -> AlertIncident | None:
        result: AlertIncident | None = None
        for rule in self.rules:
            if rule.metric_name != sample.metric_name:
                continue
            key = (rule.rule_id, sample.tenant_id, sample.terminal_id)
            history = self._history.setdefault(key, [])
            history.append(sample)
            del history[: max(0, len(history) - rule.consecutive_samples)]
            comparator = _COMPARATORS[rule.comparator]
            breached = len(history) == rule.consecutive_samples and all(
                comparator(item.value, rule.threshold) for item in history
            )
            existing = self._incidents.get(key)
            if breached:
                if existing is None or existing.status is AlertStatus.RESOLVED:
                    existing = AlertIncident(
                        incident_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        tenant_id=sample.tenant_id,
                        terminal_id=sample.terminal_id,
                        severity=rule.severity,
                        status=AlertStatus.OPEN,
                        opened_at=sample.observed_at,
                        updated_at=sample.observed_at,
                        resolved_at=None,
                        occurrence_count=1,
                        runbook=rule.runbook,
                    )
                elif sample.observed_at - existing.updated_at >= rule.cooldown:
                    existing = replace(
                        existing,
                        updated_at=sample.observed_at,
                        occurrence_count=existing.occurrence_count + 1,
                    )
                self._incidents[key] = existing
                result = existing
            elif existing is not None and existing.status is AlertStatus.OPEN:
                resolved = replace(
                    existing,
                    status=AlertStatus.RESOLVED,
                    updated_at=sample.observed_at,
                    resolved_at=sample.observed_at,
                )
                self._incidents[key] = resolved
                result = resolved
        return result
