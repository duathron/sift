"""Tests for sift.models: AlertSeverity, ClusterPriority, Alert, TriageReport."""

import uuid
from datetime import datetime, timezone

import pytest

from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    Recommendation,
    SummaryResult,
    TechniqueRef,
    TriageReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(severity: AlertSeverity = AlertSeverity.MEDIUM) -> Alert:
    return Alert(id=str(uuid.uuid4()), title="Test Alert", severity=severity)


def make_cluster(priority: ClusterPriority = ClusterPriority.MEDIUM) -> Cluster:
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=[make_alert()],
        priority=priority,
        score=0.0,
    )


def make_report(clusters: list[Cluster], alerts_ingested: int = 10, alerts_after_dedup: int = 8) -> TriageReport:
    return TriageReport(
        alerts_ingested=alerts_ingested,
        alerts_after_dedup=alerts_after_dedup,
        clusters=clusters,
        analyzed_at=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# AlertSeverity.score
# ---------------------------------------------------------------------------

class TestAlertSeverityScore:
    def test_info_score(self):
        assert AlertSeverity.INFO.score == 1

    def test_low_score(self):
        assert AlertSeverity.LOW.score == 2

    def test_medium_score(self):
        assert AlertSeverity.MEDIUM.score == 5

    def test_high_score(self):
        assert AlertSeverity.HIGH.score == 10

    def test_critical_score(self):
        assert AlertSeverity.CRITICAL.score == 20


# ---------------------------------------------------------------------------
# ClusterPriority.exit_code
# ---------------------------------------------------------------------------

class TestClusterPriorityExitCode:
    def test_critical_exit_code_is_1(self):
        assert ClusterPriority.CRITICAL.exit_code == 1

    def test_high_exit_code_is_1(self):
        assert ClusterPriority.HIGH.exit_code == 1

    def test_medium_exit_code_is_0(self):
        assert ClusterPriority.MEDIUM.exit_code == 0

    def test_low_exit_code_is_0(self):
        assert ClusterPriority.LOW.exit_code == 0

    def test_noise_exit_code_is_0(self):
        assert ClusterPriority.NOISE.exit_code == 0


# ---------------------------------------------------------------------------
# ClusterPriority.icon
# ---------------------------------------------------------------------------

class TestClusterPriorityIcon:
    def test_critical_icon(self):
        assert ClusterPriority.CRITICAL.icon == "!"

    def test_high_icon(self):
        assert ClusterPriority.HIGH.icon == "↑"

    def test_medium_icon(self):
        assert ClusterPriority.MEDIUM.icon == "~"

    def test_low_icon(self):
        assert ClusterPriority.LOW.icon == "↓"

    def test_noise_icon(self):
        assert ClusterPriority.NOISE.icon == "·"


# ---------------------------------------------------------------------------
# Alert defaults
# ---------------------------------------------------------------------------

class TestAlertDefaults:
    def test_iocs_defaults_to_empty_list(self):
        alert = make_alert()
        assert alert.iocs == []

    def test_technique_ids_defaults_to_empty_list(self):
        alert = make_alert()
        assert alert.technique_ids == []

    def test_raw_defaults_to_empty_dict(self):
        alert = make_alert()
        assert alert.raw == {}

    def test_severity_defaults_to_medium(self):
        alert = Alert(id=str(uuid.uuid4()), title="no severity set")
        assert alert.severity == AlertSeverity.MEDIUM

    def test_optional_fields_default_to_none(self):
        alert = make_alert()
        assert alert.timestamp is None
        assert alert.description is None
        assert alert.source is None
        assert alert.source_ip is None
        assert alert.dest_ip is None
        assert alert.user is None
        assert alert.host is None
        assert alert.category is None


# ---------------------------------------------------------------------------
# Alert serialization
# ---------------------------------------------------------------------------

class TestAlertSerialization:
    def test_model_dump_includes_all_fields(self):
        alert = Alert(
            id="abc-123",
            title="Suspicious Login",
            severity=AlertSeverity.HIGH,
            iocs=["10.0.0.1"],
            technique_ids=["T1078"],
            raw={"original": "record"},
        )
        data = alert.model_dump()
        assert data["id"] == "abc-123"
        assert data["title"] == "Suspicious Login"
        assert data["severity"] == AlertSeverity.HIGH
        assert data["iocs"] == ["10.0.0.1"]
        assert data["technique_ids"] == ["T1078"]
        assert data["raw"] == {"original": "record"}


# ---------------------------------------------------------------------------
# TriageReport.has_critical
# ---------------------------------------------------------------------------

class TestTriageReportHasCritical:
    def test_has_critical_true_when_critical_cluster_present(self):
        report = make_report([make_cluster(ClusterPriority.CRITICAL)])
        assert report.has_critical is True

    def test_has_critical_false_when_no_critical_cluster(self):
        report = make_report([
            make_cluster(ClusterPriority.HIGH),
            make_cluster(ClusterPriority.MEDIUM),
        ])
        assert report.has_critical is False

    def test_has_critical_false_with_empty_clusters(self):
        report = make_report([])
        assert report.has_critical is False


# ---------------------------------------------------------------------------
# TriageReport.exit_code
# ---------------------------------------------------------------------------

class TestTriageReportExitCode:
    def test_exit_code_1_with_critical_cluster(self):
        report = make_report([make_cluster(ClusterPriority.CRITICAL)])
        assert report.exit_code == 1

    def test_exit_code_1_with_high_cluster(self):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        assert report.exit_code == 1

    def test_exit_code_0_with_medium_only(self):
        report = make_report([make_cluster(ClusterPriority.MEDIUM)])
        assert report.exit_code == 0

    def test_exit_code_0_with_low_only(self):
        report = make_report([make_cluster(ClusterPriority.LOW)])
        assert report.exit_code == 0

    def test_exit_code_0_with_noise_only(self):
        report = make_report([make_cluster(ClusterPriority.NOISE)])
        assert report.exit_code == 0

    def test_exit_code_1_when_high_mixed_with_lower(self):
        """A single HIGH cluster among MEDIUM/LOW/NOISE clusters triggers exit_code=1."""
        report = make_report([
            make_cluster(ClusterPriority.MEDIUM),
            make_cluster(ClusterPriority.HIGH),
            make_cluster(ClusterPriority.NOISE),
        ])
        assert report.exit_code == 1

    def test_exit_code_0_with_empty_clusters(self):
        report = make_report([])
        assert report.exit_code == 0


# ---------------------------------------------------------------------------
# TriageReport.alerts_after_dedup
# ---------------------------------------------------------------------------

class TestTriageReportAlertsAfterDedup:
    def test_alerts_after_dedup_stores_correct_value(self):
        report = make_report(clusters=[], alerts_ingested=100, alerts_after_dedup=73)
        assert report.alerts_after_dedup == 73

    def test_alerts_after_dedup_can_equal_ingested(self):
        """No duplicates: after_dedup == ingested."""
        report = make_report(clusters=[], alerts_ingested=50, alerts_after_dedup=50)
        assert report.alerts_after_dedup == 50
