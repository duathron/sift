"""Characterization tests for the iocs json contract (S1 pre-condition).

These tests pin what must NOT change as we add iocs_typed:
- clusters[*].alerts[*].iocs is always a JSON array of strings
- clusters[*].iocs is always a JSON array of strings
- redacted iocs serialize as [] (not null/missing) in export_json
- the sift-side collect path (runner.collect_iocs_from_report) returns list[str]

All four must stay GREEN throughout every subsequent S1 task.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sift.enrichers.runner import EnrichmentRunner
from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority, TriageReport
from sift.output.export import export_json

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(iocs: list[str] | None = None) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Characterization Test Alert",
        severity=AlertSeverity.HIGH,
        iocs=iocs or [],
    )


def _make_cluster(alerts: list[Alert], iocs: list[str] | None = None) -> Cluster:
    return Cluster(
        id=str(uuid.uuid4()),
        label="Characterization Test Cluster",
        alerts=alerts,
        priority=ClusterPriority.HIGH,
        score=10.0,
        iocs=iocs or [],
    )


def _make_report(clusters: list[Cluster]) -> TriageReport:
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Task 0.1 — Alert.iocs is a JSON array of strings
# ---------------------------------------------------------------------------


class TestAlertIocsIsListOfStrings:
    """0.1: alert iocs serialises as JSON array of str."""

    def test_alert_iocs_is_json_array_of_strings(self):
        ioc_values = ["1.2.3.4", "evil.com", "aabbccdd" * 8]  # ip, domain, sha256-length
        alert = _make_alert(iocs=ioc_values)
        cluster = _make_cluster(alerts=[alert], iocs=ioc_values)
        report = _make_report(clusters=[cluster])

        data = json.loads(export_json(report))
        alert_iocs = data["clusters"][0]["alerts"][0]["iocs"]

        assert isinstance(alert_iocs, list), "iocs must be a JSON array"
        assert all(isinstance(v, str) for v in alert_iocs), "every iocs entry must be a string"
        assert set(alert_iocs) == set(ioc_values)

    def test_alert_iocs_empty_by_default_in_json(self):
        alert = _make_alert(iocs=[])
        cluster = _make_cluster(alerts=[alert], iocs=[])
        report = _make_report(clusters=[cluster])

        data = json.loads(export_json(report))
        alert_iocs = data["clusters"][0]["alerts"][0]["iocs"]

        assert alert_iocs == []


# ---------------------------------------------------------------------------
# Task 0.2 — Cluster.iocs is a JSON array of strings
# ---------------------------------------------------------------------------


class TestClusterIocsIsListOfStrings:
    """0.2: cluster iocs serialises as JSON array of str."""

    def test_cluster_iocs_is_json_array_of_strings(self):
        ioc_values = ["185.220.101.47", "malware.example.net"]
        alert = _make_alert(iocs=ioc_values)
        cluster = _make_cluster(alerts=[alert], iocs=ioc_values)
        report = _make_report(clusters=[cluster])

        data = json.loads(export_json(report))
        cluster_iocs = data["clusters"][0]["iocs"]

        assert isinstance(cluster_iocs, list), "cluster iocs must be a JSON array"
        assert all(isinstance(v, str) for v in cluster_iocs), "every cluster iocs entry must be a string"
        assert set(cluster_iocs) == set(ioc_values)

    def test_cluster_iocs_empty_by_default_in_json(self):
        alert = _make_alert(iocs=[])
        cluster = _make_cluster(alerts=[alert], iocs=[])
        report = _make_report(clusters=[cluster])

        data = json.loads(export_json(report))
        assert data["clusters"][0]["iocs"] == []


# ---------------------------------------------------------------------------
# Task 0.3 — Redacted iocs serialises as [] in export_json
# ---------------------------------------------------------------------------


class TestRedactedIocsIsEmptyListInJson:
    """0.3: an alert redacted on iocs serialises iocs==[] (not null/missing)."""

    def test_redacted_iocs_is_empty_list_in_json(self):
        alert = _make_alert(iocs=["1.2.3.4", "evil.com"])
        redacted = alert.redact(["iocs"])
        cluster = _make_cluster(alerts=[redacted], iocs=[])
        report = _make_report(clusters=[cluster])

        data = json.loads(export_json(report))
        alert_iocs = data["clusters"][0]["alerts"][0]["iocs"]

        assert alert_iocs == [], f"Expected [], got {alert_iocs!r}"
        assert "iocs" in data["clusters"][0]["alerts"][0], "iocs key must be present even when empty"

    def test_redacted_iocs_is_list_not_null(self):
        alert = _make_alert(iocs=["1.2.3.4"])
        redacted = alert.redact(["iocs"])

        # Direct model check before JSON round-trip
        assert redacted.iocs == [], f"Expected [], got {redacted.iocs!r}"
        assert isinstance(redacted.iocs, list)


# ---------------------------------------------------------------------------
# Task 0.4 — Vex bridge wire format is list[str]
# ---------------------------------------------------------------------------


class TestVexBridgeWireFormatIsStrings:
    """0.4: collect_iocs_from_report returns list[str] — the wire format vex reads."""

    def test_collect_iocs_returns_list_of_strings(self):
        ioc_values = ["185.220.101.47", "evil.com", "a" * 64]
        alert = _make_alert(iocs=ioc_values)
        cluster = _make_cluster(alerts=[alert], iocs=ioc_values)
        report = _make_report(clusters=[cluster])

        result = EnrichmentRunner.collect_iocs_from_report(report)

        assert isinstance(result, list), "collect_iocs must return list"
        assert all(isinstance(v, str) for v in result), "every IOC must be str"
        assert set(result) == set(ioc_values)

    def test_collect_iocs_deduplicates_across_clusters(self):
        shared_ioc = "185.220.101.47"
        cluster1 = _make_cluster(alerts=[_make_alert(iocs=[shared_ioc])], iocs=[shared_ioc])
        cluster2 = _make_cluster(alerts=[_make_alert(iocs=[shared_ioc, "evil.com"])], iocs=[shared_ioc, "evil.com"])
        report = _make_report(clusters=[cluster1, cluster2])

        result = EnrichmentRunner.collect_iocs_from_report(report)

        assert result.count(shared_ioc) == 1, "shared IOC must appear exactly once"
        assert all(isinstance(v, str) for v in result)
