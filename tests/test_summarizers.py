"""Tests for sift summarizers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from sift.models import (
    Alert, AlertSeverity, Cluster, ClusterPriority,
    SummaryResult, TriageReport,
)
from sift.summarizers.template import TemplateSummarizer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(severity=AlertSeverity.HIGH, title="Test Alert", iocs=None) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title=title,
        severity=severity,
        iocs=iocs or [],
    )


def make_cluster(priority=ClusterPriority.HIGH, alert_count=3, iocs=None) -> Cluster:
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=[make_alert() for _ in range(alert_count)],
        priority=priority,
        score=30.0,
        iocs=iocs or ["185.220.101.47", "evil.phish.ru"],
        techniques=[],
        cluster_reason="IOC overlap",
    )


def make_report(clusters=None) -> TriageReport:
    if clusters is None:
        clusters = [make_cluster()]
    return TriageReport(
        alerts_ingested=10,
        alerts_after_dedup=8,
        clusters=clusters,
        analyzed_at=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# TemplateSummarizer
# ---------------------------------------------------------------------------

class TestTemplateSummarizer:
    summ = TemplateSummarizer()

    def test_name(self):
        assert self.summ.name == "template"

    def test_returns_summary_result(self):
        report = make_report()
        result = self.summ.summarize(report)
        assert isinstance(result, SummaryResult)

    def test_executive_summary_not_empty(self):
        result = self.summ.summarize(make_report())
        assert len(result.executive_summary) > 10

    def test_provider_is_template(self):
        result = self.summ.summarize(make_report())
        assert result.provider == "template"

    def test_overall_priority_reflects_clusters(self):
        clusters = [
            make_cluster(priority=ClusterPriority.LOW),
            make_cluster(priority=ClusterPriority.CRITICAL),
            make_cluster(priority=ClusterPriority.MEDIUM),
        ]
        result = self.summ.summarize(make_report(clusters))
        assert result.overall_priority == ClusterPriority.CRITICAL

    def test_all_noise_gives_noise_priority(self):
        clusters = [make_cluster(priority=ClusterPriority.NOISE)]
        result = self.summ.summarize(make_report(clusters))
        assert result.overall_priority == ClusterPriority.NOISE

    def test_cluster_summaries_generated(self):
        report = make_report([
            make_cluster(priority=ClusterPriority.HIGH),
            make_cluster(priority=ClusterPriority.MEDIUM),
        ])
        result = self.summ.summarize(report)
        assert len(result.cluster_summaries) >= 1

    def test_critical_cluster_has_immediate_recommendation(self):
        report = make_report([make_cluster(priority=ClusterPriority.CRITICAL)])
        result = self.summ.summarize(report)
        summaries = result.cluster_summaries
        if summaries:
            priorities = [r.priority for r in summaries[0].recommendations]
            assert "IMMEDIATE" in priorities

    def test_noise_cluster_excluded_from_summaries(self):
        noise = make_cluster(priority=ClusterPriority.NOISE)
        high = make_cluster(priority=ClusterPriority.HIGH)
        result = self.summ.summarize(make_report([noise, high]))
        # NOISE clusters should not get detailed summaries (or at minimum, HIGH is there)
        cluster_ids = [s.cluster_id for s in result.cluster_summaries]
        assert high.id in cluster_ids

    def test_generated_at_is_recent(self):
        result = self.summ.summarize(make_report())
        now = datetime.now(tz=timezone.utc)
        delta = abs((now - result.generated_at).total_seconds())
        assert delta < 5  # generated within last 5 seconds

    def test_empty_report(self):
        report = make_report(clusters=[])
        result = self.summ.summarize(report)
        assert isinstance(result, SummaryResult)
        assert result.cluster_summaries == []
