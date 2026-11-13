from datetime import UTC, datetime
import unittest

from techflex_cloud_foundation.server.observability.alerts import (
    AlertEvaluator,
    AlertStatus,
    default_alert_rules,
)
from techflex_cloud_foundation.server.observability.events import SLISample


def sample(metric_name: str, value: float, minute: int) -> SLISample:
    return SLISample(
        metric_name=metric_name,
        value=value,
        observed_at=datetime(2026, 7, 20, 9, minute, tzinfo=UTC),
        tenant_id="tenant-a",
        terminal_id="terminal-a",
    )


class AlertEvaluatorTests(unittest.TestCase):
    def test_default_rules_cover_required_operational_alerts(self) -> None:
        metric_names = {rule.metric_name for rule in default_alert_rules()}

        self.assertTrue(
            {
                "error_rate",
                "upload_backlog_sessions",
                "terminal_offline_seconds",
                "manifest_conflicts",
                "analysis_failures",
            }.issubset(metric_names)
        )
        self.assertTrue(all(rule.runbook for rule in default_alert_rules()))

    def test_alert_requires_the_configured_consecutive_window(self) -> None:
        rule = next(
            rule for rule in default_alert_rules() if rule.metric_name == "analysis_failures"
        )
        evaluator = AlertEvaluator((rule,))

        self.assertIsNone(evaluator.observe(sample("analysis_failures", 1, 0)))
        self.assertIsNone(evaluator.observe(sample("analysis_failures", 1, 1)))
        incident = evaluator.observe(sample("analysis_failures", 1, 2))

        self.assertEqual(incident.status, AlertStatus.OPEN)
        self.assertEqual(incident.rule_id, rule.rule_id)
        self.assertEqual(incident.occurrence_count, 1)

    def test_open_alert_is_deduplicated_during_cooldown(self) -> None:
        rule = next(
            rule for rule in default_alert_rules() if rule.metric_name == "manifest_conflicts"
        )
        evaluator = AlertEvaluator((rule,))

        first = evaluator.observe(sample("manifest_conflicts", 1, 0))
        duplicate = evaluator.observe(sample("manifest_conflicts", 1, 1))

        self.assertEqual(first.incident_id, duplicate.incident_id)
        self.assertEqual(duplicate.occurrence_count, 1)

    def test_healthy_sample_resolves_an_open_alert(self) -> None:
        rule = next(
            rule for rule in default_alert_rules() if rule.metric_name == "manifest_conflicts"
        )
        evaluator = AlertEvaluator((rule,))
        opened = evaluator.observe(sample("manifest_conflicts", 1, 0))

        resolved = evaluator.observe(sample("manifest_conflicts", 0, 1))

        self.assertEqual(opened.incident_id, resolved.incident_id)
        self.assertEqual(resolved.status, AlertStatus.RESOLVED)
        self.assertIsNotNone(resolved.resolved_at)


if __name__ == "__main__":
    unittest.main()
