"""Tests for sift.summarizers.template.TemplateSummarizer."""

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
from sift.summarizers.template import TemplateSummarizer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(severity: AlertSeverity = AlertSeverity.HIGH, iocs: list[str] | None = None) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Phishing Email",
        severity=severity,
        iocs=iocs or ["185.220.101.47"],
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
        iocs=iocs or ["185.220.101.47"],
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

class TestTemplateSummarizerProtocol:
    """TemplateSummarizer satisfies the structural SummarizerProtocol."""

    def test_implements_summarizer_protocol(self):
        assert isinstance(TemplateSummarizer(), SummarizerProtocol)

    def test_name_is_template(self):
        assert TemplateSummarizer().name == "template"


class TestTemplateSummarizerReturnType:
    """summarize() returns a well-formed SummaryResult."""

    def test_summarize_returns_summary_result(self):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        result = TemplateSummarizer().summarize(report)
        assert isinstance(result, SummaryResult)

    def test_executive_summary_is_non_empty_string(self):
        report = make_report([make_cluster(ClusterPriority.MEDIUM)])
        result = TemplateSummarizer().summarize(report)
        assert isinstance(result.executive_summary, str)
        assert len(result.executive_summary) > 0

    def test_provider_field_is_template(self):
        report = make_report([make_cluster(ClusterPriority.LOW)])
        result = TemplateSummarizer().summarize(report)
        assert result.provider == "template"


class TestTemplateSummarizerOverallPriority:
    """overall_priority reflects the highest cluster priority in the report."""

    def test_overall_priority_critical_when_cluster_is_critical(self):
        report = make_report([make_cluster(ClusterPriority.CRITICAL)])
        result = TemplateSummarizer().summarize(report)
        assert result.overall_priority == ClusterPriority.CRITICAL

    def test_overall_priority_noise_when_all_clusters_are_noise(self):
        clusters = [make_cluster(ClusterPriority.NOISE), make_cluster(ClusterPriority.NOISE)]
        report = make_report(clusters)
        result = TemplateSummarizer().summarize(report)
        assert result.overall_priority == ClusterPriority.NOISE


class TestTemplateSummarizerClusterSummaries:
    """cluster_summaries coverage and NOISE filtering."""

    def test_cluster_summaries_one_entry_per_non_noise_cluster(self):
        clusters = [
            make_cluster(ClusterPriority.HIGH),
            make_cluster(ClusterPriority.MEDIUM),
        ]
        report = make_report(clusters)
        result = TemplateSummarizer().summarize(report)
        assert len(result.cluster_summaries) == 2

    def test_noise_clusters_excluded_from_cluster_summaries(self):
        clusters = [
            make_cluster(ClusterPriority.HIGH),
            make_cluster(ClusterPriority.NOISE),
            make_cluster(ClusterPriority.NOISE),
        ]
        report = make_report(clusters)
        result = TemplateSummarizer().summarize(report)
        assert len(result.cluster_summaries) == 1


class TestTemplateSummarizerRecommendations:
    """Recommendations carry the correct priority tier per cluster level."""

    def test_critical_cluster_recommendations_include_immediate_action(self):
        report = make_report([make_cluster(ClusterPriority.CRITICAL)])
        result = TemplateSummarizer().summarize(report)
        priorities = {r.priority for cs in result.cluster_summaries for r in cs.recommendations}
        assert "IMMEDIATE" in priorities

    def test_high_cluster_recommendations_include_within_1h_action(self):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        result = TemplateSummarizer().summarize(report)
        priorities = {r.priority for cs in result.cluster_summaries for r in cs.recommendations}
        assert "WITHIN_1H" in priorities

    def test_medium_cluster_recommendations_include_within_24h_action(self):
        report = make_report([make_cluster(ClusterPriority.MEDIUM)])
        result = TemplateSummarizer().summarize(report)
        priorities = {r.priority for cs in result.cluster_summaries for r in cs.recommendations}
        assert "WITHIN_24H" in priorities


class TestTemplateSummarizerNarrative:
    """Cluster narratives surface IOC and ATT&CK content."""

    def test_narrative_contains_ioc_info(self):
        ioc = "185.220.101.47"
        cluster = make_cluster(ClusterPriority.HIGH, iocs=[ioc])
        report = make_report([cluster])
        result = TemplateSummarizer().summarize(report)
        assert len(result.cluster_summaries) == 1
        narrative = result.cluster_summaries[0].narrative
        # The template reports the IOC count or the first IOC value
        assert ioc in narrative or "IOC" in narrative

    def test_narrative_contains_technique_info_when_present(self):
        techniques = [
            TechniqueRef(
                technique_id="T1566.001",
                technique_name="Spearphishing Attachment",
                tactic="Initial Access",
            )
        ]
        cluster = make_cluster(ClusterPriority.HIGH, techniques=techniques)
        report = make_report([cluster])
        result = TemplateSummarizer().summarize(report)
        narrative = result.cluster_summaries[0].narrative
        assert "ATT&CK" in narrative or "T1566.001" in narrative


class TestTemplateSummarizerEdgeCases:
    """Edge-case resilience."""

    def test_empty_clusters_no_crash_and_executive_summary_generated(self):
        report = make_report([])
        result = TemplateSummarizer().summarize(report)
        assert isinstance(result.executive_summary, str)
        assert len(result.executive_summary) > 0
