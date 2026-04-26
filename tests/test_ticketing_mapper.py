"""Tests for sift.ticketing.mapper — TriageReport → TicketDraft conversion."""

from datetime import datetime, timezone

import pytest

from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    ClusterSummary,
    Recommendation,
    SummaryResult,
    TechniqueRef,
    TriageReport,
)
from sift.ticketing.mapper import (
    _build_timeline,
    _build_title,
    _top_cluster,
    _top_severity,
    report_to_draft,
    top_clusters_for_ticket,
)


def _alert(
    id: str = "a1",
    title: str = "Test Alert",
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    timestamp: datetime | None = None,
    iocs: list[str] | None = None,
) -> Alert:
    return Alert(
        id=id,
        title=title,
        severity=severity,
        timestamp=timestamp,
        iocs=iocs or [],
    )


def _cluster(
    id: str = "c1",
    label: str = "Test Cluster",
    alerts: list[Alert] | None = None,
    priority: ClusterPriority = ClusterPriority.HIGH,
    score: float = 10.0,
    confidence: float = 0.85,
    iocs: list[str] | None = None,
    techniques: list[TechniqueRef] | None = None,
) -> Cluster:
    return Cluster(
        id=id,
        label=label,
        alerts=alerts or [_alert()],
        priority=priority,
        score=score,
        confidence=confidence,
        iocs=iocs or [],
        techniques=techniques or [],
        cluster_reason="test",
    )


def _report(clusters: list[Cluster], summary: SummaryResult | None = None) -> TriageReport:
    return TriageReport(
        input_file="test.json",
        alerts_ingested=5,
        alerts_after_dedup=5,
        clusters=clusters,
        summary=summary,
        analyzed_at=datetime(2026, 4, 20, 10, 0, 0, tzinfo=timezone.utc),
    )


class TestTopCluster:
    def test_picks_critical_over_high(self):
        crit = _cluster(id="c1", priority=ClusterPriority.CRITICAL, score=50.0)
        high = _cluster(id="c2", priority=ClusterPriority.HIGH, score=200.0)
        report = _report([high, crit])
        assert _top_cluster(report).id == "c1"

    def test_breaks_tie_by_score(self):
        h1 = _cluster(id="h1", priority=ClusterPriority.HIGH, score=100.0)
        h2 = _cluster(id="h2", priority=ClusterPriority.HIGH, score=200.0)
        report = _report([h1, h2])
        assert _top_cluster(report).id == "h2"

    def test_returns_none_for_empty_report(self):
        report = _report([])
        assert _top_cluster(report) is None


class TestTopSeverity:
    def test_returns_max_severity(self):
        alerts = [
            _alert(severity=AlertSeverity.LOW),
            _alert(severity=AlertSeverity.CRITICAL),
            _alert(severity=AlertSeverity.MEDIUM),
        ]
        cluster = _cluster(alerts=alerts)
        assert _top_severity(cluster) == "CRITICAL"

    def test_empty_cluster_defaults_medium(self):
        cluster = _cluster(alerts=[])
        assert _top_severity(cluster) == "MEDIUM"


class TestBuildTitle:
    def test_format(self):
        cluster = _cluster(label="Credential Dumping + Lateral Movement")
        title = _build_title(cluster, "CRITICAL")
        assert title.startswith("[sift] CRITICAL |")
        assert "Credential Dumping" in title

    def test_long_label_truncated(self):
        cluster = _cluster(label="A" * 100)
        title = _build_title(cluster, "HIGH")
        assert len(title) <= 80 + len("[sift] HIGH | ")


class TestBuildTimeline:
    def test_sorted_by_timestamp(self):
        t1 = datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 4, 20, 10, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc)
        alerts = [
            _alert(id="a1", title="Second", timestamp=t1),
            _alert(id="a2", title="Third", timestamp=t2),
            _alert(id="a3", title="First", timestamp=t3),
        ]
        cluster = _cluster(alerts=alerts)
        lines = _build_timeline(cluster)
        assert lines[0].endswith("First")
        assert lines[1].endswith("Second")
        assert lines[2].endswith("Third")

    def test_overflow_line_shown(self):
        alerts = [_alert(id=f"a{i}", timestamp=datetime(2026, 4, 20, i, 0, tzinfo=timezone.utc)) for i in range(12)]
        cluster = _cluster(alerts=alerts)
        lines = _build_timeline(cluster)
        assert any("more alert" in l for l in lines)

    def test_no_timestamp_shows_unknown(self):
        cluster = _cluster(alerts=[_alert(timestamp=None)])
        lines = _build_timeline(cluster)
        assert "unknown time" in lines[0]


class TestReportToDraft:
    def test_raises_on_empty_report(self):
        with pytest.raises(ValueError, match="no clusters"):
            report_to_draft(_report([]))

    def test_uses_specified_cluster(self):
        c1 = _cluster(id="c1", priority=ClusterPriority.CRITICAL)
        c2 = _cluster(id="c2", priority=ClusterPriority.LOW)
        report = _report([c1, c2])
        draft = report_to_draft(report, cluster=c2)
        assert draft.evidence["cluster_id"] == "c2"

    def test_auto_picks_top_cluster(self):
        crit = _cluster(id="crit", priority=ClusterPriority.CRITICAL)
        low = _cluster(id="low", priority=ClusterPriority.LOW)
        draft = report_to_draft(_report([low, crit]))
        assert draft.evidence["cluster_id"] == "crit"

    def test_severity_from_alerts(self):
        alerts = [_alert(severity=AlertSeverity.CRITICAL), _alert(severity=AlertSeverity.LOW)]
        cluster = _cluster(alerts=alerts, priority=ClusterPriority.CRITICAL)
        draft = report_to_draft(_report([cluster]))
        assert draft.severity == "CRITICAL"

    def test_priority_mapping_critical(self):
        cluster = _cluster(priority=ClusterPriority.CRITICAL)
        draft = report_to_draft(_report([cluster]))
        assert draft.priority == "IMMEDIATE"

    def test_priority_mapping_high(self):
        cluster = _cluster(priority=ClusterPriority.HIGH)
        draft = report_to_draft(_report([cluster]))
        assert draft.priority == "WITHIN_1H"

    def test_iocs_from_cluster(self):
        cluster = _cluster(iocs=["1.2.3.4", "evil.com"])
        draft = report_to_draft(_report([cluster]))
        assert "1.2.3.4" in draft.iocs

    def test_technique_ids_extracted(self):
        techniques = [TechniqueRef(technique_id="T1003", technique_name="", tactic="")]
        cluster = _cluster(techniques=techniques)
        draft = report_to_draft(_report([cluster]))
        assert "T1003" in draft.technique_ids

    def test_auto_summary_when_no_llm(self):
        cluster = _cluster()
        draft = report_to_draft(_report([cluster]))
        assert "HIGH/CRITICAL" in draft.summary or "Cluster" in draft.summary

    def test_recommendations_from_summary(self):
        cluster = _cluster(id="c1")
        rec = Recommendation(action="Isolate dc01", priority="IMMEDIATE", rationale="Evidence of lateral movement")
        cs = ClusterSummary(cluster_id="c1", narrative="Attack detected.", recommendations=[rec])
        summary = SummaryResult(
            executive_summary="Critical incident detected.",
            cluster_summaries=[cs],
            overall_priority=ClusterPriority.CRITICAL,
            provider="template",
            generated_at=datetime(2026, 4, 20, tzinfo=timezone.utc),
        )
        draft = report_to_draft(_report([cluster], summary=summary))
        assert "Isolate dc01" in draft.recommendations

    def test_narrative_used_when_available(self):
        cluster = _cluster(id="c1")
        cs = ClusterSummary(cluster_id="c1", narrative="Specific narrative from LLM.")
        summary = SummaryResult(
            executive_summary="Critical incident detected.",
            cluster_summaries=[cs],
            overall_priority=ClusterPriority.HIGH,
            provider="anthropic",
            generated_at=datetime(2026, 4, 20, tzinfo=timezone.utc),
        )
        draft = report_to_draft(_report([cluster], summary=summary))
        assert draft.summary == "Specific narrative from LLM."

    def test_source_file_populated(self):
        draft = report_to_draft(_report([_cluster()]))
        assert draft.source_file == "test.json"

    def test_sift_version_present(self):
        from sift import __version__
        draft = report_to_draft(_report([_cluster()]))
        assert draft.sift_version == __version__

    def test_confidence_from_cluster(self):
        cluster = _cluster(confidence=0.80)
        draft = report_to_draft(_report([cluster]))
        assert draft.confidence == 0.80


class TestTopClustersForTicket:
    def test_returns_high_and_critical_only(self):
        clusters = [
            _cluster(id="crit", priority=ClusterPriority.CRITICAL, score=50),
            _cluster(id="high", priority=ClusterPriority.HIGH, score=30),
            _cluster(id="med", priority=ClusterPriority.MEDIUM, score=10),
            _cluster(id="low", priority=ClusterPriority.LOW, score=5),
        ]
        result = top_clusters_for_ticket(_report(clusters))
        ids = [c.id for c in result]
        assert "crit" in ids
        assert "high" in ids
        assert "med" not in ids
        assert "low" not in ids

    def test_sorted_by_score_desc(self):
        clusters = [
            _cluster(id="h1", priority=ClusterPriority.HIGH, score=10),
            _cluster(id="h2", priority=ClusterPriority.HIGH, score=50),
        ]
        result = top_clusters_for_ticket(_report(clusters))
        assert result[0].id == "h2"
