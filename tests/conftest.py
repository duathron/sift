"""Pytest fixtures for sift tests."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority, TriageReport
from sift.normalizers.generic import GenericNormalizer

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Individual alert fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_alert_info() -> Alert:
    """Minimal INFO-severity alert."""
    return Alert(
        id="test-info-001",
        timestamp=datetime(2026, 3, 22, 8, 0, 0, tzinfo=timezone.utc),
        severity=AlertSeverity.INFO,
        title="Scheduled Task Created",
        description="A scheduled task was registered on the host.",
        source="sysmon",
        source_ip=None,
        dest_ip=None,
        user=None,
        host="workstation-01",
        category="Execution",
        iocs=[],
        technique_ids=[],
        raw={},
    )


@pytest.fixture
def sample_alert_high() -> Alert:
    """HIGH-severity alert with network IOCs."""
    return Alert(
        id="test-high-001",
        timestamp=datetime(2026, 3, 22, 9, 15, 0, tzinfo=timezone.utc),
        severity=AlertSeverity.HIGH,
        title="DNS Query to Phishing Domain",
        description="A host resolved a known phishing domain.",
        source="dns-sensor",
        source_ip="10.0.0.1",
        dest_ip="185.220.101.47",
        user="jsmith",
        host="workstation-02",
        category="Phishing",
        iocs=["185.220.101.47", "evil.phish.ru"],
        technique_ids=["T1566.002"],
        raw={"query": "evil.phish.ru", "response": "185.220.101.47"},
    )


@pytest.fixture
def sample_alert_critical() -> Alert:
    """CRITICAL-severity ransomware alert."""
    return Alert(
        id="test-critical-001",
        timestamp=datetime(2026, 3, 22, 9, 30, 0, tzinfo=timezone.utc),
        severity=AlertSeverity.CRITICAL,
        title="Ransomware Encryption Activity Detected",
        description="Mass file encryption observed across multiple directories.",
        source="edr",
        source_ip="10.0.0.5",
        dest_ip=None,
        user="jsmith",
        host="fileserver-01",
        category="Ransomware",
        iocs=["c2.ransomgroup.onion"],
        technique_ids=["T1486"],
        raw={"files_encrypted": 2341, "extension": ".locked"},
    )


# ---------------------------------------------------------------------------
# File-backed fixtures (normalised from JSON fixtures)
# ---------------------------------------------------------------------------


@pytest.fixture
def phishing_alerts(tmp_path) -> list[Alert]:
    """Alerts normalised from tests/fixtures/phishing_campaign.json."""
    fixture_path = FIXTURES_DIR / "phishing_campaign.json"
    raw_data = json.loads(fixture_path.read_text(encoding="utf-8"))
    normalizer = GenericNormalizer()
    return normalizer.normalize(raw_data)


@pytest.fixture
def lateral_alerts(tmp_path) -> list[Alert]:
    """Alerts normalised from tests/fixtures/lateral_movement.json."""
    fixture_path = FIXTURES_DIR / "lateral_movement.json"
    raw_data = json.loads(fixture_path.read_text(encoding="utf-8"))
    normalizer = GenericNormalizer()
    return normalizer.normalize(raw_data)


@pytest.fixture
def mixed_alerts(tmp_path) -> list[Alert]:
    """Alerts normalised from tests/fixtures/mixed.json."""
    fixture_path = FIXTURES_DIR / "mixed.json"
    raw_data = json.loads(fixture_path.read_text(encoding="utf-8"))
    normalizer = GenericNormalizer()
    return normalizer.normalize(raw_data)


# ---------------------------------------------------------------------------
# Cluster and report fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_cluster(sample_alert_high: Alert, sample_alert_critical: Alert) -> Cluster:
    """Cluster containing the HIGH and CRITICAL sample alerts."""
    return Cluster(
        id="cluster-test-001",
        label="Phishing + Ransomware Activity",
        alerts=[sample_alert_high, sample_alert_critical],
        priority=ClusterPriority.HIGH,
        score=30.0,
        confidence=0.85,
        techniques=["T1566.002", "T1486"],
        iocs=["185.220.101.47", "evil.phish.ru", "c2.ransomgroup.onion"],
        first_seen=sample_alert_high.timestamp,
        last_seen=sample_alert_critical.timestamp,
        cluster_reason="Shared user 'jsmith' across phishing and ransomware events.",
    )


@pytest.fixture
def sample_report(sample_cluster: Cluster) -> TriageReport:
    """Minimal TriageReport with one cluster and no AI summary."""
    return TriageReport(
        input_file="test_alerts.json",
        alerts_ingested=2,
        alerts_after_dedup=2,
        clusters=[sample_cluster],
        summary=None,
        enrichment={},
        manifest={},
        analyzed_at=datetime(2026, 3, 22, 10, 0, 0, tzinfo=timezone.utc),
    )
