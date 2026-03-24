"""Tests for sift.pipeline.chunker: chunk_alerts and merge_triage_reports."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sift.config import ClusteringConfig
from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority, TriageReport
from sift.pipeline.chunker import chunk_alerts, merge_triage_reports


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert(n: int) -> Alert:
    return Alert(id=f"alert-{n:04d}", title=f"Alert {n}", severity=AlertSeverity.MEDIUM)


def _alerts(count: int) -> list[Alert]:
    return [_alert(i) for i in range(count)]


def _cluster(score: float = 10.0, priority: ClusterPriority = ClusterPriority.MEDIUM) -> Cluster:
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=[_alert(0)],
        priority=priority,
        score=score,
    )


def _report(
    clusters: list[Cluster] | None = None,
    alerts_ingested: int = 10,
    alerts_after_dedup: int = 8,
) -> TriageReport:
    return TriageReport(
        input_file="test.json",
        alerts_ingested=alerts_ingested,
        alerts_after_dedup=alerts_after_dedup,
        clusters=clusters or [],
        analyzed_at=datetime(2026, 3, 24, 12, 0, 0, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# chunk_alerts
# ---------------------------------------------------------------------------

class TestChunkAlerts:
    def test_basic_split(self):
        alerts = _alerts(10)
        chunks = chunk_alerts(alerts, 3)
        assert len(chunks) == 4
        assert [len(c) for c in chunks] == [3, 3, 3, 1]
        flat = [a for chunk in chunks for a in chunk]
        assert flat == alerts

    def test_exact_multiple(self):
        chunks = chunk_alerts(_alerts(9), 3)
        assert len(chunks) == 3
        assert all(len(c) == 3 for c in chunks)

    def test_size_zero_no_chunking(self):
        alerts = _alerts(5)
        chunks = chunk_alerts(alerts, 0)
        assert len(chunks) == 1
        assert chunks[0] == alerts

    def test_negative_size_no_chunking(self):
        alerts = _alerts(5)
        chunks = chunk_alerts(alerts, -1)
        assert len(chunks) == 1
        assert chunks[0] == alerts

    def test_size_larger_than_list(self):
        alerts = _alerts(5)
        chunks = chunk_alerts(alerts, 100)
        assert len(chunks) == 1
        assert chunks[0] == alerts

    def test_empty_list(self):
        chunks = chunk_alerts([], 3)
        assert isinstance(chunks, list)
        flat = [a for chunk in chunks for a in chunk]
        assert flat == []

    def test_size_one(self):
        alerts = _alerts(3)
        chunks = chunk_alerts(alerts, 1)
        assert len(chunks) == 3
        assert all(len(c) == 1 for c in chunks)
        assert [c[0] for c in chunks] == alerts


# ---------------------------------------------------------------------------
# merge_triage_reports
# ---------------------------------------------------------------------------

class TestMergeTriageReports:
    def test_merge_empty(self):
        result = merge_triage_reports([])
        assert result.alerts_ingested == 0
        assert result.alerts_after_dedup == 0
        assert result.clusters == []

    def test_merge_single(self):
        r = _report(clusters=[_cluster(score=5.0)], alerts_ingested=3, alerts_after_dedup=3)
        result = merge_triage_reports([r])
        assert result is r

    def test_clusters_combined(self):
        r1 = _report(clusters=[_cluster(10.0), _cluster(5.0)])
        r2 = _report(clusters=[_cluster(20.0), _cluster(1.0)])
        result = merge_triage_reports([r1, r2])
        assert len(result.clusters) == 4

    def test_sorted_by_score_descending(self):
        r1 = _report(clusters=[_cluster(score=1.0), _cluster(score=50.0)])
        r2 = _report(clusters=[_cluster(score=10.0)])
        result = merge_triage_reports([r1, r2])
        scores = [c.score for c in result.clusters]
        assert scores == sorted(scores, reverse=True)

    def test_total_alerts_summed(self):
        r1 = _report(alerts_ingested=100, alerts_after_dedup=90)
        r2 = _report(alerts_ingested=200, alerts_after_dedup=180)
        result = merge_triage_reports([r1, r2])
        assert result.alerts_ingested == 300
        assert result.alerts_after_dedup == 270

    def test_metadata_from_first_report(self):
        t1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2026, 6, 1, tzinfo=timezone.utc)
        r1 = TriageReport(input_file="first.json", alerts_ingested=1, alerts_after_dedup=1, clusters=[], analyzed_at=t1)
        r2 = TriageReport(input_file="second.json", alerts_ingested=1, alerts_after_dedup=1, clusters=[], analyzed_at=t2)
        result = merge_triage_reports([r1, r2])
        assert result.input_file == "first.json"
        assert result.analyzed_at == t1


# ---------------------------------------------------------------------------
# ClusteringConfig.chunk_size
# ---------------------------------------------------------------------------

class TestChunkSizeConfig:
    def test_default_is_zero(self):
        assert ClusteringConfig().chunk_size == 0

    def test_custom_chunk_size(self):
        assert ClusteringConfig(chunk_size=500).chunk_size == 500
