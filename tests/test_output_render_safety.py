from datetime import datetime, timezone
from types import SimpleNamespace

from rich.console import Console

from sift.models import ClusterPriority, SummaryResult
from sift.output.formatter import _render_executive_summary
from sift.output.md import render_md_report


def test_render_executive_summary_escapes_markup_at_console():
    hostile = "[bold]spoof[/bold] \x1b[31mansi\x1b[0m"
    report = SimpleNamespace(summary=SimpleNamespace(overall_priority=ClusterPriority.HIGH, executive_summary=hostile))
    con = Console(record=True, force_terminal=True, width=200)
    _render_executive_summary(report, con)
    out = con.export_text()
    assert "[bold]" in out  # markup literal, not consumed
    assert "\x1b[31m" not in out  # ANSI stripped


def test_render_md_report_escapes_executive_summary(sample_report):
    hostile = "danger <script>alert(1)</script> end"
    summary = SummaryResult(
        executive_summary=hostile,
        overall_priority=ClusterPriority.HIGH,
        provider="anthropic",
        generated_at=datetime(2026, 3, 22, tzinfo=timezone.utc),
    )
    report = sample_report.model_copy(update={"summary": summary})
    md = render_md_report(report)
    assert "<script>" not in md
    assert r"\<script\>" in md
