"""Tests for sift.output.export: export_json, export_csv, export_cluster_csv."""

from __future__ import annotations

import base64
import csv
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sift.models import (
    IOC,
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    TriageReport,
)
from sift.output.export import export_cluster_csv, export_csv, export_json

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
        techniques=[],
    )


def make_report(clusters: list[Cluster]) -> TriageReport:
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# export_json tests
# ---------------------------------------------------------------------------


class TestExportJson:
    """export_json produces valid, correct JSON."""

    def test_returns_valid_json_string(self):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        result = export_json(report)
        # Must not raise
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_contains_correct_alert_count(self):
        alerts = [make_alert(), make_alert()]
        report = make_report([make_cluster(ClusterPriority.HIGH, alerts=alerts)])
        data = json.loads(export_json(report))
        assert data["alerts_ingested"] == 2

    def test_writes_file_when_path_provided(self, tmp_path: Path):
        report = make_report([make_cluster(ClusterPriority.MEDIUM)])
        out_file = tmp_path / "report.json"
        result = export_json(report, path=out_file)
        assert out_file.exists()
        assert json.loads(out_file.read_text()) == json.loads(result)

    def test_no_clusters_produces_empty_clusters_list(self):
        report = make_report([])
        data = json.loads(export_json(report))
        assert data["clusters"] == []


# ---------------------------------------------------------------------------
# export_csv tests
# ---------------------------------------------------------------------------


class TestExportCsv:
    """export_csv produces a flat per-alert CSV."""

    def test_returns_parseable_csv_string(self):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        result = export_csv(report)
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) >= 1

    def test_columns_include_required_fields(self):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        result = export_csv(report)
        reader = csv.DictReader(io.StringIO(result))
        fieldnames = reader.fieldnames or []
        assert "alert_id" in fieldnames
        assert "alert_severity" in fieldnames
        assert "cluster_priority" in fieldnames

    def test_row_count_equals_total_alerts_across_clusters(self):
        cluster_a = make_cluster(ClusterPriority.HIGH, alerts=[make_alert(), make_alert()])
        cluster_b = make_cluster(ClusterPriority.MEDIUM, alerts=[make_alert()])
        report = make_report([cluster_a, cluster_b])
        result = export_csv(report)
        rows = list(csv.DictReader(io.StringIO(result)))
        assert len(rows) == 3

    def test_writes_file_when_path_provided(self, tmp_path: Path):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        out_file = tmp_path / "alerts.csv"
        export_csv(report, path=out_file)
        assert out_file.exists()
        content = out_file.read_text()
        assert "alert_id" in content

    def test_iocs_are_pipe_separated_in_cell(self):
        alert = make_alert(iocs=["1.2.3.4", "evil.example.com"])
        report = make_report([make_cluster(ClusterPriority.HIGH, alerts=[alert])])
        result = export_csv(report)
        rows = list(csv.DictReader(io.StringIO(result)))
        assert rows[0]["alert_iocs"] == "1.2.3.4|evil.example.com"


# ---------------------------------------------------------------------------
# export_cluster_csv tests
# ---------------------------------------------------------------------------


class TestExportClusterCsv:
    """export_cluster_csv produces a per-cluster summary CSV."""

    def test_returns_parseable_csv_string(self):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        result = export_cluster_csv(report)
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) >= 1

    def test_columns_include_required_fields(self):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        result = export_cluster_csv(report)
        reader = csv.DictReader(io.StringIO(result))
        fieldnames = reader.fieldnames or []
        assert "cluster_id" in fieldnames
        assert "priority" in fieldnames
        assert "alert_count" in fieldnames

    def test_row_count_equals_cluster_count(self):
        clusters = [
            make_cluster(ClusterPriority.CRITICAL),
            make_cluster(ClusterPriority.HIGH),
            make_cluster(ClusterPriority.MEDIUM),
        ]
        report = make_report(clusters)
        result = export_cluster_csv(report)
        rows = list(csv.DictReader(io.StringIO(result)))
        assert len(rows) == 3

    def test_writes_file_when_path_provided(self, tmp_path: Path):
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        out_file = tmp_path / "clusters.csv"
        export_cluster_csv(report, path=out_file)
        assert out_file.exists()
        content = out_file.read_text()
        assert "cluster_id" in content


# ---------------------------------------------------------------------------
# Task 7 — ps_encoded scrub must cover iocs_typed[].value (no raw b64 leak)
# ---------------------------------------------------------------------------


def _make_ps_ioc() -> str:
    """Build a ps_encoded:<b64> IOC value (100+ chars required by extractor)."""
    payload = b"Write-Host 'evil'" * 10  # ensures 100+ base64 chars
    b64 = base64.b64encode(payload).decode()
    return f"ps_encoded:{b64}"


class TestPsEncodedScrubInIocsTyped:
    def test_ps_encoded_scrubbed_in_iocs_typed(self):
        """export_json must scrub ps_encoded raw b64 from both iocs AND iocs_typed[].value."""
        ps_ioc = _make_ps_ioc()
        raw_b64 = ps_ioc[len("ps_encoded:") :]

        alert = Alert(
            id=str(uuid.uuid4()),
            title="PS test",
            severity=AlertSeverity.HIGH,
            iocs=[ps_ioc],
            iocs_typed=[IOC(value=ps_ioc, type="ps_encoded")],
        )
        cluster = make_cluster(
            ClusterPriority.HIGH,
            alerts=[alert],
            iocs=[ps_ioc],
        )
        # Also set iocs_typed on the cluster
        cluster = cluster.model_copy(update={"iocs_typed": [IOC(value=ps_ioc, type="ps_encoded")]})
        report = make_report([cluster])

        json_out = export_json(report)

        # Raw base64 must NEVER appear in output
        assert raw_b64 not in json_out, "Raw base64 payload leaked into JSON output"

        # Both iocs and iocs_typed must have the stub form
        data = json.loads(json_out)
        alert_data = data["clusters"][0]["alerts"][0]
        assert all(v.startswith("ps_encoded:") and len(v) < len(ps_ioc) for v in alert_data["iocs"])
        assert all(
            entry["value"].startswith("ps_encoded:") and len(entry["value"]) < len(ps_ioc)
            for entry in alert_data["iocs_typed"]
        )

    def test_non_ps_ioc_unchanged_in_iocs_typed(self):
        """Non-ps_encoded IOCs must pass through sanitization unchanged."""
        ioc = "185.220.101.47"
        alert = Alert(
            id=str(uuid.uuid4()),
            title="IP test",
            severity=AlertSeverity.HIGH,
            iocs=[ioc],
            iocs_typed=[IOC(value=ioc, type="ip")],
        )
        cluster = make_cluster(ClusterPriority.HIGH, alerts=[alert], iocs=[ioc])
        cluster = cluster.model_copy(update={"iocs_typed": [IOC(value=ioc, type="ip")]})
        report = make_report([cluster])

        data = json.loads(export_json(report))
        typed_entries = data["clusters"][0]["alerts"][0]["iocs_typed"]
        assert typed_entries[0]["value"] == ioc
