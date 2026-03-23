"""Tests for sift.metrics: TriageMetrics collection and formatting."""

import uuid
from datetime import datetime, timezone

from rich.table import Table

from sift.metrics import MetricsCollector
from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority, TriageReport

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(
    category: str | None = None,
    severity: AlertSeverity = AlertSeverity.MEDIUM,
) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Test Alert",
        severity=severity,
        category=category,
    )


def make_cluster(
    priority: ClusterPriority = ClusterPriority.MEDIUM,
    alert_count: int = 3,
    iocs: list[str] | None = None,
) -> Cluster:
    alerts = [make_alert(category="Malware") for _ in range(alert_count)]
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=alerts,
        priority=priority,
        score=10.0,
        iocs=iocs or [],
    )


def make_report(
    clusters: list[Cluster] | None = None,
    alerts_ingested: int = 10,
    alerts_after_dedup: int = 8,
) -> TriageReport:
    if clusters is None:
        clusters = [make_cluster()]
    return TriageReport(
        alerts_ingested=alerts_ingested,
        alerts_after_dedup=alerts_after_dedup,
        clusters=clusters,
        analyzed_at=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# TestMetricsCollection
# ---------------------------------------------------------------------------


class TestMetricsCollection:
    def test_basic_collection(self):
        """Test basic metric collection from a simple report."""
        cluster = make_cluster(alert_count=5)
        report = make_report(clusters=[cluster])

        metrics = MetricsCollector.collect(report)

        assert metrics.cluster_count == 1
        assert metrics.alert_count == 5
        assert metrics.ai_success_rate == 0.0  # no summary

    def test_avg_cluster_size_calculation(self):
        """Test average cluster size calculation."""
        c1 = make_cluster(alert_count=2)
        c2 = make_cluster(alert_count=8)
        report = make_report(clusters=[c1, c2])

        metrics = MetricsCollector.collect(report)

        assert metrics.cluster_count == 2
        assert metrics.alert_count == 10
        assert abs(metrics.avg_cluster_size - 5.0) < 0.01

    def test_top_categories_extraction(self):
        """Test extraction of top categories."""
        c1 = make_cluster(alert_count=3)
        c1.alerts = [
            make_alert(category="Malware"),
            make_alert(category="Malware"),
            make_alert(category="Phishing"),
        ]
        c2 = make_cluster(alert_count=2)
        c2.alerts = [
            make_alert(category="Phishing"),
            make_alert(category="Lateral Movement"),
        ]
        report = make_report(clusters=[c1, c2])

        metrics = MetricsCollector.collect(report)

        assert "Malware" in metrics.top_categories
        assert metrics.top_categories["Malware"] == 2
        assert metrics.top_categories["Phishing"] == 2

    def test_ioc_distribution_counting(self):
        """Test IOC distribution counting."""
        c1 = make_cluster(iocs=["192.168.1.1", "192.168.1.2", "example.com"])
        c2 = make_cluster(iocs=["10.0.0.1", "badhost.io"])
        report = make_report(clusters=[c1, c2])

        metrics = MetricsCollector.collect(report)

        assert metrics.ioc_distribution["ipv4"] == 3
        assert metrics.ioc_distribution["domain"] == 2

    def test_ai_success_rate_calculation(self):
        """Test AI success rate calculation (no summary)."""
        cluster = make_cluster(alert_count=5)
        report = make_report(clusters=[cluster])

        metrics = MetricsCollector.collect(report)

        assert metrics.ai_success_rate == 0.0

    def test_zero_clusters_edge_case(self):
        """Test metrics with zero clusters."""
        report = make_report(clusters=[])

        metrics = MetricsCollector.collect(report)

        assert metrics.cluster_count == 0
        assert metrics.alert_count == 0
        assert metrics.avg_cluster_size == 0.0


# ---------------------------------------------------------------------------
# TestMetricsFormatting
# ---------------------------------------------------------------------------


class TestMetricsFormatting:
    def test_table_formatting(self):
        """Test Rich Table formatting of metrics."""
        cluster = make_cluster(alert_count=5, iocs=["192.168.1.1"])
        cluster.alerts = [make_alert(category="Malware") for _ in range(5)]
        report = make_report(clusters=[cluster])

        metrics = MetricsCollector.collect(report)
        table = MetricsCollector.format_table(metrics)

        assert isinstance(table, Table)
        assert table.title == "Triage Metrics"

    def test_table_with_categories_and_iocs(self):
        """Test table formatting with populated categories and IOCs."""
        c1 = make_cluster(
            alert_count=2,
            iocs=["192.168.1.1", "example.com", "abc123def456"],
        )
        c1.alerts = [
            make_alert(category="Malware"),
            make_alert(category="Malware"),
        ]
        report = make_report(clusters=[c1])

        metrics = MetricsCollector.collect(report)
        table = MetricsCollector.format_table(metrics)

        assert isinstance(table, Table)
        # Categories should be in output
        assert metrics.top_categories["Malware"] == 2

    def test_table_zero_clusters(self):
        """Test table formatting with zero clusters."""
        report = make_report(clusters=[])

        metrics = MetricsCollector.collect(report)
        table = MetricsCollector.format_table(metrics)

        assert isinstance(table, Table)
        assert metrics.cluster_count == 0


# ---------------------------------------------------------------------------
# TestIOCClassification
# ---------------------------------------------------------------------------


class TestIOCClassification:
    def test_classify_ipv4(self):
        """Test IPv4 classification."""
        types = MetricsCollector._classify_iocs(["192.168.1.1", "10.0.0.1"])
        assert types == ["ipv4", "ipv4"]

    def test_classify_domain(self):
        """Test domain classification."""
        types = MetricsCollector._classify_iocs(["example.com", "malware.io"])
        assert types == ["domain", "domain"]

    def test_classify_url(self):
        """Test URL classification."""
        types = MetricsCollector._classify_iocs(["http://example.com", "ftp://files.io"])
        assert types == ["url", "url"]

    def test_classify_hash(self):
        """Test hash classification."""
        types = MetricsCollector._classify_iocs([
            "5d41402abc4b2a76b9719d911017c592",  # MD5
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # SHA1
            "2c26b46911185131006ba32987d1b2b82df7e0e3a8c0b7349349b1acb7b65f18",  # SHA256
        ])
        assert types == ["md5", "sha1", "sha256"]

    def test_classify_email(self):
        """Test email classification."""
        types = MetricsCollector._classify_iocs(["user@example.com"])
        assert types == ["email"]

    def test_classify_mixed(self):
        """Test mixed IOC types."""
        types = MetricsCollector._classify_iocs([
            "192.168.1.1",
            "example.com",
            "http://malware.io",
            "user@phish.com",
        ])
        assert types == ["ipv4", "domain", "url", "email"]
