"""Tests for S3: HTML and Markdown output formats.

TDD — written before production code.

Covers:
  - HTML output is parseable (contains expected structure)
  - HTML contains cluster + IOC data
  - Markdown output is well-formed
  - Markdown contains cluster + IOC data
  - Redacted fields stay redacted in both formats
  - Existing json/csv/stix format paths are not altered
  - _render_output accepts 'html' and 'md' format strings
"""

from __future__ import annotations

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

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_alert(
    iocs: list[str] | None = None,
    severity: AlertSeverity = AlertSeverity.HIGH,
    user: str = "jsmith",
    source_ip: str = "10.0.0.1",
) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Phishing Alert",
        severity=severity,
        user=user,
        source_ip=source_ip,
        iocs=iocs or ["185.220.101.47"],
        iocs_typed=[IOC(value=ioc, type="ip") for ioc in (iocs or ["185.220.101.47"])],
    )


def _make_cluster(
    priority: ClusterPriority = ClusterPriority.HIGH,
    label: str = "Phishing Campaign",
    iocs: list[str] | None = None,
    alerts: list[Alert] | None = None,
) -> Cluster:
    _iocs = iocs or ["185.220.101.47"]
    _alerts = alerts or [_make_alert(iocs=_iocs)]
    return Cluster(
        id=str(uuid.uuid4()),
        label=label,
        alerts=_alerts,
        priority=priority,
        score=30.0,
        iocs=_iocs,
        iocs_typed=[IOC(value=i, type="ip") for i in _iocs],
    )


def _make_report(clusters: list[Cluster] | None = None) -> TriageReport:
    _clusters = clusters or [_make_cluster()]
    return TriageReport(
        input_file="test_alerts.json",
        alerts_ingested=sum(len(c.alerts) for c in _clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in _clusters),
        clusters=_clusters,
        analyzed_at=datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Import the new modules (these will fail until production code exists)
# ---------------------------------------------------------------------------


class TestHtmlModuleImport:
    """sift.output.html module must exist and be importable."""

    def test_module_importable(self):
        from sift.output import html as sift_html  # noqa: F401

    def test_render_html_function_exists(self):
        from sift.output.html import render_html_report

        assert callable(render_html_report)


class TestMdModuleImport:
    """sift.output.md module must exist and be importable."""

    def test_module_importable(self):
        from sift.output import md as sift_md  # noqa: F401

    def test_render_md_function_exists(self):
        from sift.output.md import render_md_report

        assert callable(render_md_report)


# ---------------------------------------------------------------------------
# HTML output content tests
# ---------------------------------------------------------------------------


class TestHtmlOutput:
    """render_html_report produces valid, correct HTML."""

    def _render(self, report: TriageReport) -> str:
        from sift.output.html import render_html_report

        return render_html_report(report)

    def test_returns_string(self):
        html = self._render(_make_report())
        assert isinstance(html, str)

    def test_is_valid_html_structure(self):
        html = self._render(_make_report())
        assert "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()
        assert "<html" in html
        assert "</html>" in html
        assert "<body" in html
        assert "</body>" in html

    def test_contains_cluster_label(self):
        report = _make_report([_make_cluster(label="RansomwareCluster-XYZ")])
        html = self._render(report)
        assert "RansomwareCluster-XYZ" in html

    def test_contains_ioc_value(self):
        report = _make_report([_make_cluster(iocs=["185.220.101.47"])])
        html = self._render(report)
        assert "185.220.101.47" in html

    def test_contains_priority(self):
        report = _make_report([_make_cluster(priority=ClusterPriority.CRITICAL)])
        html = self._render(report)
        assert "CRITICAL" in html

    def test_has_title_element(self):
        html = self._render(_make_report())
        assert "<title>" in html

    def test_contains_sift_branding(self):
        html = self._render(_make_report())
        assert "sift" in html.lower()

    def test_multiple_clusters_all_present(self):
        c1 = _make_cluster(label="ClusterAlpha", iocs=["1.1.1.1"])
        c2 = _make_cluster(label="ClusterBeta", iocs=["2.2.2.2"])
        report = _make_report([c1, c2])
        html = self._render(report)
        assert "ClusterAlpha" in html
        assert "ClusterBeta" in html

    def test_html_has_head_section(self):
        html = self._render(_make_report())
        assert "<head" in html
        assert "</head>" in html


class TestHtmlRedaction:
    """Redacted fields must not appear in the HTML output."""

    def _render_redacted(self, fields: list[str]) -> str:
        from sift.output.html import render_html_report

        alert = _make_alert(source_ip="10.0.0.99", user="secret_user")
        redacted_alert = alert.redact(fields)
        cluster = _make_cluster(alerts=[redacted_alert])
        # Manually set iocs on cluster to be empty if "iocs" was redacted
        report = _make_report([cluster])
        return render_html_report(report)

    def test_source_ip_redacted_not_in_html(self):
        html = self._render_redacted(["source_ip"])
        assert "10.0.0.99" not in html

    def test_user_redacted_shows_redacted_marker(self):
        html = self._render_redacted(["user"])
        assert "secret_user" not in html


# ---------------------------------------------------------------------------
# Markdown output content tests
# ---------------------------------------------------------------------------


class TestMdOutput:
    """render_md_report produces valid, correct Markdown."""

    def _render(self, report: TriageReport) -> str:
        from sift.output.md import render_md_report

        return render_md_report(report)

    def test_returns_string(self):
        md = self._render(_make_report())
        assert isinstance(md, str)

    def test_contains_cluster_label(self):
        report = _make_report([_make_cluster(label="LateralMovement-ABC")])
        md = self._render(report)
        assert "LateralMovement-ABC" in md

    def test_contains_ioc_value(self):
        report = _make_report([_make_cluster(iocs=["185.220.101.47"])])
        md = self._render(report)
        assert "185.220.101.47" in md

    def test_contains_priority(self):
        report = _make_report([_make_cluster(priority=ClusterPriority.HIGH)])
        md = self._render(report)
        assert "HIGH" in md

    def test_has_markdown_headings(self):
        """Markdown output must contain at least one # heading."""
        md = self._render(_make_report())
        assert md.strip().startswith("#") or "\n#" in md

    def test_contains_sift_branding(self):
        md = self._render(_make_report())
        assert "sift" in md.lower()

    def test_multiple_clusters_all_present(self):
        c1 = _make_cluster(label="ClusterAlpha", iocs=["1.1.1.1"])
        c2 = _make_cluster(label="ClusterBeta", iocs=["2.2.2.2"])
        report = _make_report([c1, c2])
        md = self._render(report)
        assert "ClusterAlpha" in md
        assert "ClusterBeta" in md

    def test_alert_count_present(self):
        cluster = _make_cluster(alerts=[_make_alert(), _make_alert()])
        report = _make_report([cluster])
        md = self._render(report)
        assert "2" in md  # at least the count appears somewhere


class TestMdRedaction:
    """Redacted fields must not appear in the Markdown output."""

    def _render_redacted(self, fields: list[str]) -> str:
        from sift.output.md import render_md_report

        alert = _make_alert(source_ip="10.0.0.77", user="secret_user_md")
        redacted_alert = alert.redact(fields)
        cluster = _make_cluster(alerts=[redacted_alert])
        report = _make_report([cluster])
        return render_md_report(report)

    def test_source_ip_redacted_not_in_md(self):
        md = self._render_redacted(["source_ip"])
        assert "10.0.0.77" not in md

    def test_user_redacted_not_in_md(self):
        md = self._render_redacted(["user"])
        assert "secret_user_md" not in md


# ---------------------------------------------------------------------------
# _render_output dispatch: html and md are accepted formats
# ---------------------------------------------------------------------------


class TestRenderOutputDispatch:
    """_render_output must accept 'html' and 'md' format strings."""

    def test_render_output_html_to_file(self, tmp_path: Path):
        from sift.config import AppConfig
        from sift.main import _render_output

        report = _make_report()
        out = tmp_path / "report.html"
        cfg = AppConfig()
        # Must not raise
        _render_output(report, format="html", output_path=out, cfg=cfg, quiet=True)
        assert out.exists()
        content = out.read_text()
        assert "<html" in content.lower()

    def test_render_output_md_to_file(self, tmp_path: Path):
        from sift.config import AppConfig
        from sift.main import _render_output

        report = _make_report()
        out = tmp_path / "report.md"
        cfg = AppConfig()
        _render_output(report, format="md", output_path=out, cfg=cfg, quiet=True)
        assert out.exists()
        content = out.read_text()
        assert "#" in content  # Has markdown headings

    def test_render_output_html_stdout(self, tmp_path: Path, capsys):
        """html format without output_path prints to stdout."""
        from sift.config import AppConfig
        from sift.main import _render_output

        report = _make_report()
        cfg = AppConfig()
        _render_output(report, format="html", output_path=None, cfg=cfg, quiet=True)
        captured = capsys.readouterr()
        assert "<html" in captured.out.lower()

    def test_render_output_md_stdout(self, tmp_path: Path, capsys):
        """md format without output_path prints to stdout."""
        from sift.config import AppConfig
        from sift.main import _render_output

        report = _make_report()
        cfg = AppConfig()
        _render_output(report, format="md", output_path=None, cfg=cfg, quiet=True)
        captured = capsys.readouterr()
        assert "#" in captured.out


# ---------------------------------------------------------------------------
# Regression: existing format paths must not be altered
# ---------------------------------------------------------------------------


class TestExistingFormatsUnchanged:
    """Ensure JSON, CSV, STIX paths are not broken by S3 changes."""

    def test_json_format_still_works(self, tmp_path: Path):
        import json

        from sift.config import AppConfig
        from sift.main import _render_output

        report = _make_report()
        out = tmp_path / "report.json"
        cfg = AppConfig()
        _render_output(report, format="json", output_path=out, cfg=cfg, quiet=True)
        data = json.loads(out.read_text())
        assert "clusters" in data

    def test_csv_format_still_works(self, tmp_path: Path):
        from sift.config import AppConfig
        from sift.main import _render_output

        report = _make_report()
        out = tmp_path / "report.csv"
        cfg = AppConfig()
        _render_output(report, format="csv", output_path=out, cfg=cfg, quiet=True)
        content = out.read_text()
        assert "alert_id" in content  # Header row present
