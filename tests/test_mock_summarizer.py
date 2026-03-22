"""Tests for sift.summarizers.mock.MockSummarizer."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    SummaryResult,
    TechniqueRef,
    TriageReport,
)
from sift.summarizers.protocol import SummarizerProtocol
from sift.summarizers.mock import MockSummarizer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(severity: AlertSeverity = AlertSeverity.HIGH, iocs: list[str] | None = None) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Test Alert",
        severity=severity,
        iocs=iocs or ["192.168.1.1"],
    )


def make_cluster(
    priority: ClusterPriority,
    alerts: list[Alert] | None = None,
    techniques: list[TechniqueRef] | None = None,
    iocs: list[str] | None = None,
) -> Cluster:
    alerts = alerts or [make_alert()]
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=alerts,
        priority=priority,
        score=50.0,
        iocs=iocs or ["192.168.1.1"],
        techniques=techniques or [],
    )


def make_report(clusters: list[Cluster]) -> TriageReport:
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMockSummarizerProtocol:
    """MockSummarizer satisfies the structural SummarizerProtocol."""

    def test_implements_summarizer_protocol(self):
        """MockSummarizer is recognized as implementing SummarizerProtocol."""
        assert isinstance(MockSummarizer(), SummarizerProtocol)

    def test_name_is_mock(self):
        """The provider name is exactly 'mock'."""
        assert MockSummarizer().name == "mock"


class TestMockSummarizerReturnType:
    """summarize() returns a well-formed SummaryResult."""

    def test_summarize_returns_summary_result(self):
        """summarize() returns a SummaryResult instance."""
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        result = MockSummarizer().summarize(report)
        assert isinstance(result, SummaryResult)

    def test_executive_summary_is_non_empty_string(self):
        """The executive_summary field is a non-empty string."""
        report = make_report([make_cluster(ClusterPriority.MEDIUM)])
        result = MockSummarizer().summarize(report)
        assert isinstance(result.executive_summary, str)
        assert len(result.executive_summary) > 0

    def test_provider_field_is_mock(self):
        """The provider field is set to 'mock'."""
        report = make_report([make_cluster(ClusterPriority.LOW)])
        result = MockSummarizer().summarize(report)
        assert result.provider == "mock"

    def test_generated_at_is_datetime(self):
        """The generated_at field is a datetime in UTC."""
        report = make_report([make_cluster(ClusterPriority.MEDIUM)])
        result = MockSummarizer().summarize(report)
        assert isinstance(result.generated_at, datetime)
        assert result.generated_at.tzinfo == timezone.utc


class TestMockSummarizerDeterminism:
    """MockSummarizer is fully deterministic: same input → same output."""

    def test_same_input_produces_same_output(self):
        """Calling summarize twice with the same report produces identical results."""
        cluster = make_cluster(ClusterPriority.HIGH, iocs=["192.168.1.1", "192.168.1.2"])
        report = make_report([cluster])

        summarizer = MockSummarizer()
        result1 = summarizer.summarize(report)
        result2 = summarizer.summarize(report)

        assert result1.executive_summary == result2.executive_summary
        assert result1.overall_priority == result2.overall_priority
        assert len(result1.cluster_summaries) == len(result2.cluster_summaries)

    def test_deterministic_with_multiple_clusters(self):
        """Determinism holds across multiple clusters."""
        clusters = [
            make_cluster(ClusterPriority.CRITICAL),
            make_cluster(ClusterPriority.HIGH),
            make_cluster(ClusterPriority.MEDIUM),
        ]
        report = make_report(clusters)

        summarizer = MockSummarizer()
        result1 = summarizer.summarize(report)
        result2 = summarizer.summarize(report)

        assert result1.overall_priority == result2.overall_priority
        assert len(result1.cluster_summaries) == len(result2.cluster_summaries)

    def test_deterministic_with_empty_clusters(self):
        """Determinism holds even with no clusters."""
        report = make_report([])
        summarizer = MockSummarizer()

        result1 = summarizer.summarize(report)
        result2 = summarizer.summarize(report)

        assert result1.executive_summary == result2.executive_summary
        assert result1.overall_priority == result2.overall_priority


class TestMockSummarizerZeroExternalDependencies:
    """MockSummarizer makes no external API calls."""

    def test_no_network_calls_on_summarize(self):
        """summarize() completes without any network activity."""
        # This is a behavioral test: if summarize tries to make a network call,
        # the test would fail in isolated or offline environments.
        # The mock implementation should not import any HTTP clients.
        report = make_report([make_cluster(ClusterPriority.HIGH)])

        # Should complete without error in any environment
        result = MockSummarizer().summarize(report)
        assert result is not None


class TestMockSummarizerEmptyClusters:
    """MockSummarizer handles edge cases gracefully."""

    def test_empty_clusters_produces_valid_result(self):
        """An empty clusters list produces valid output."""
        report = make_report([])
        result = MockSummarizer().summarize(report)

        assert isinstance(result, SummaryResult)
        assert isinstance(result.executive_summary, str)
        assert len(result.executive_summary) > 0
        assert result.overall_priority == ClusterPriority.NOISE

    def test_all_noise_clusters_produces_noise_overall_priority(self):
        """All NOISE clusters → overall_priority is NOISE."""
        clusters = [
            make_cluster(ClusterPriority.NOISE),
            make_cluster(ClusterPriority.NOISE),
        ]
        report = make_report(clusters)
        result = MockSummarizer().summarize(report)

        assert result.overall_priority == ClusterPriority.NOISE

    def test_noise_clusters_excluded_from_cluster_summaries(self):
        """NOISE clusters are not included in cluster_summaries."""
        clusters = [
            make_cluster(ClusterPriority.HIGH),
            make_cluster(ClusterPriority.NOISE),
            make_cluster(ClusterPriority.NOISE),
        ]
        report = make_report(clusters)
        result = MockSummarizer().summarize(report)

        # Only 1 non-NOISE cluster summary
        assert len(result.cluster_summaries) == 1


class TestMockSummarizerOverallPriority:
    """overall_priority reflects the highest cluster priority in the report."""

    def test_overall_priority_reflects_critical_cluster(self):
        """CRITICAL cluster sets overall_priority to CRITICAL."""
        report = make_report([make_cluster(ClusterPriority.CRITICAL)])
        result = MockSummarizer().summarize(report)
        assert result.overall_priority == ClusterPriority.CRITICAL

    def test_overall_priority_reflects_highest_when_mixed(self):
        """With mixed priorities, overall_priority is the highest."""
        clusters = [
            make_cluster(ClusterPriority.LOW),
            make_cluster(ClusterPriority.HIGH),
            make_cluster(ClusterPriority.MEDIUM),
        ]
        report = make_report(clusters)
        result = MockSummarizer().summarize(report)
        assert result.overall_priority == ClusterPriority.HIGH


class TestMockSummarizerIntegrationWithTriageReport:
    """MockSummarizer integrates well with full TriageReport workflows."""

    def test_summarize_with_complete_cluster_data(self):
        """MockSummarizer processes clusters with full metadata."""
        cluster = make_cluster(
            priority=ClusterPriority.HIGH,
            iocs=["192.168.1.1", "10.0.0.1", "evil.example.com"],
            techniques=[
                TechniqueRef(
                    technique_id="T1566.001",
                    technique_name="Spearphishing Attachment",
                    tactic="Initial Access",
                )
            ],
        )
        report = make_report([cluster])
        result = MockSummarizer().summarize(report)

        assert result.provider == "mock"
        assert len(result.cluster_summaries) == 1
        assert "T1566.001" in result.cluster_summaries[0].narrative

    def test_summarize_produces_recommendations(self):
        """Cluster summaries include recommendations."""
        report = make_report([make_cluster(ClusterPriority.CRITICAL)])
        result = MockSummarizer().summarize(report)

        assert len(result.cluster_summaries) > 0
        cluster_summary = result.cluster_summaries[0]
        assert len(cluster_summary.recommendations) > 0
        # Critical clusters should have IMMEDIATE actions
        priorities = {r.priority for r in cluster_summary.recommendations}
        assert "IMMEDIATE" in priorities


class TestMockSummarizerMultipleInstances:
    """Multiple MockSummarizer instances behave consistently."""

    def test_different_instances_same_output(self):
        """Different MockSummarizer instances produce identical results."""
        report = make_report([make_cluster(ClusterPriority.MEDIUM)])

        summarizer1 = MockSummarizer()
        summarizer2 = MockSummarizer()

        result1 = summarizer1.summarize(report)
        result2 = summarizer2.summarize(report)

        assert result1.executive_summary == result2.executive_summary
        assert result1.overall_priority == result2.overall_priority
