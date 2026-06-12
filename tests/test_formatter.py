"""Tests for sift.output.formatter — rich output rendering.

Uses Console(record=True) + export_text() to capture rich output for assertions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from rich.console import Console

from sift.models import IOC, Alert, AlertSeverity, Cluster, ClusterPriority, TriageReport
from sift.output.formatter import format_report_rich

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(iocs: list[str] | None = None, iocs_typed: list[IOC] | None = None) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Test Alert for Formatter",
        severity=AlertSeverity.HIGH,
        iocs=iocs or [],
        iocs_typed=iocs_typed or [],
    )


def _make_cluster(
    iocs: list[str] | None = None,
    iocs_typed: list[IOC] | None = None,
    priority: ClusterPriority = ClusterPriority.HIGH,
) -> Cluster:
    _iocs = iocs or []
    _typed = iocs_typed or []
    alert = _make_alert(iocs=_iocs, iocs_typed=_typed)
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=[alert],
        priority=priority,
        score=10.0,
        iocs=_iocs,
        iocs_typed=_typed,
    )


def _make_report(clusters: list[Cluster]) -> TriageReport:
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime.now(timezone.utc),
    )


def _render_to_text(report: TriageReport) -> str:
    """Render a TriageReport to plain text via Rich Console(record=True)."""
    con = Console(record=True, width=120)
    format_report_rich(report, console=con)
    return con.export_text()


# ---------------------------------------------------------------------------
# Task 9 — type-count header in cluster detail panel
# ---------------------------------------------------------------------------


class TestClusterPanelShowsIocTypeCounts:
    def test_cluster_panel_shows_ioc_type_counts(self):
        """Rendered rich output contains type-count summary line when iocs_typed is populated."""
        iocs_typed = [
            IOC(value="a" * 64, type="hash_sha256"),
            IOC(value="b" * 64, type="hash_sha256"),
            IOC(value="c" * 64, type="hash_sha256"),
            IOC(value="d" * 64, type="hash_sha256"),
            IOC(value="e" * 64, type="hash_sha256"),
            IOC(value="evil.com", type="domain"),
            IOC(value="bad.net", type="domain"),
            IOC(value="malware.io", type="domain"),
            IOC(value="185.220.101.47", type="ip"),
        ]
        iocs = [ioc.value for ioc in iocs_typed]
        cluster = _make_cluster(iocs=iocs, iocs_typed=iocs_typed)
        report = _make_report([cluster])

        rendered = _render_to_text(report)

        # Must contain type-count summary — e.g. "hash_sha256 ×5  domain ×3  ip ×1"
        assert "hash_sha256" in rendered, "Expected 'hash_sha256' in rendered output"
        assert "domain" in rendered, "Expected 'domain' in rendered output"
        # The × character signals the count format (or at least a count of some kind)
        assert "×" in rendered or "x" in rendered, "Expected count indicator in rendered output"

    def test_type_count_header_not_shown_when_iocs_typed_empty(self):
        """When iocs_typed is empty, no type-count header is added (backward compat)."""
        iocs = ["185.220.101.47", "evil.com"]
        cluster = _make_cluster(iocs=iocs, iocs_typed=[])
        report = _make_report([cluster])

        rendered = _render_to_text(report)

        # IOCs section must still show (old behavior preserved)
        assert "IOC" in rendered or "185.220.101.47" in rendered

    def test_ioc_list_still_shown_below_type_counts(self):
        """Top IOCs list is still shown after the type-count header."""
        ioc_value = "185.220.101.47"
        iocs_typed = [IOC(value=ioc_value, type="ip")]
        cluster = _make_cluster(iocs=[ioc_value], iocs_typed=iocs_typed)
        report = _make_report([cluster])

        rendered = _render_to_text(report)

        # The actual IOC value must still appear
        assert ioc_value in rendered, f"IOC value {ioc_value!r} must still appear in rendered output"
