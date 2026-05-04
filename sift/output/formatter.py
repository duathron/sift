"""Rich and console output formatting for sift triage reports."""

from __future__ import annotations

from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import base64
import hashlib

from ..models import (
    AlertSeverity,
    Cluster,
    ClusterPriority,
    ClusterSummary,
    TriageReport,
)
from ..pipeline.ioc_extractor import classify_severity_hint

# ---------------------------------------------------------------------------
# Style maps
# ---------------------------------------------------------------------------

_PRIORITY_STYLE: dict[ClusterPriority, str] = {
    ClusterPriority.CRITICAL: "bold red",
    ClusterPriority.HIGH: "red",
    ClusterPriority.MEDIUM: "yellow",
    ClusterPriority.LOW: "cyan",
    ClusterPriority.NOISE: "dim",
}

_SEVERITY_STYLE: dict[AlertSeverity, str] = {
    AlertSeverity.CRITICAL: "bold red",
    AlertSeverity.HIGH: "red",
    AlertSeverity.MEDIUM: "yellow",
    AlertSeverity.LOW: "cyan",
    AlertSeverity.INFO: "blue",
}

# Sort order for display: CRITICAL first
_PRIORITY_ORDER: dict[ClusterPriority, int] = {
    ClusterPriority.CRITICAL: 0,
    ClusterPriority.HIGH: 1,
    ClusterPriority.MEDIUM: 2,
    ClusterPriority.LOW: 3,
    ClusterPriority.NOISE: 4,
}

_RECOMMENDATION_PRIORITY_STYLE: dict[str, str] = {
    "IMMEDIATE": "bold red",
    "WITHIN_1H": "red",
    "WITHIN_24H": "yellow",
    "MONITOR": "cyan",
}

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def severity_color(sev: AlertSeverity) -> str:
    """Return a Rich color/style string for the given alert severity."""
    return _SEVERITY_STYLE.get(sev, "white")


def priority_color(pri: ClusterPriority) -> str:
    """Return a Rich color/style string for the given cluster priority."""
    return _PRIORITY_STYLE.get(pri, "white")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _priority_label(pri: ClusterPriority) -> Text:
    """Colored icon + name for a cluster priority."""
    style = priority_color(pri)
    return Text(f"{pri.icon} {pri.value}", style=style)


def _fmt_datetime(dt) -> str:
    if dt is None:
        return "–"
    return dt.strftime("%Y-%m-%d %H:%M")


def _fmt_time_range(cluster: Cluster) -> str:
    if cluster.first_seen is None and cluster.last_seen is None:
        return "–"
    first = _fmt_datetime(cluster.first_seen)
    last = _fmt_datetime(cluster.last_seen)
    if first == last:
        return first
    return f"{first} → {last}"


def _fmt_techniques(cluster: Cluster) -> str:
    ids = [t.technique_id for t in cluster.techniques]
    if not ids:
        return "–"
    shown = ids[:3]
    remainder = len(ids) - 3
    result = ", ".join(shown)
    if remainder > 0:
        result += f" +{remainder} more"
    return result


def _fmt_ps_encoded(ioc: str) -> str:
    """Replace ps_encoded:<b64> with a short human-readable label."""
    payload = ioc[len("ps_encoded:"):]
    try:
        raw = base64.b64decode(payload + "==")
        n = len(raw)
        digest = hashlib.sha256(raw).hexdigest()[:8]
    except Exception:
        digest = payload[:8]
        n = 0
    size_str = f"{n}B" if n else "?B"
    return f"ps_encoded:{digest}… ({size_str})"


def _cluster_severity_hint(cluster: Cluster) -> str | None:
    """Return the highest severity hint across a cluster's IOCs."""
    best: str | None = None
    for ioc in cluster.iocs:
        h = classify_severity_hint(ioc)
        if h == "critical":
            return "critical"
        if h == "high":
            best = "high"
    return best


def _sorted_clusters(clusters: list[Cluster]) -> list[Cluster]:
    return sorted(clusters, key=lambda c: _PRIORITY_ORDER[c.priority])


def _find_cluster_summary(report: TriageReport, cluster_id: str) -> Optional[ClusterSummary]:
    if report.summary is None:
        return None
    for cs in report.summary.cluster_summaries:
        if cs.cluster_id == cluster_id:
            return cs
    return None


def _should_show_detail(cluster: Cluster, all_clusters: list[Cluster]) -> bool:
    """Return True if a per-cluster detail panel should be rendered."""
    if cluster.priority in (ClusterPriority.CRITICAL, ClusterPriority.HIGH):
        return True
    non_noise = [c for c in all_clusters if c.priority != ClusterPriority.NOISE]
    return len(non_noise) <= 3


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _render_header(report: TriageReport, con: Console) -> None:
    """Print the header panel with run metadata."""
    overall = report.summary.overall_priority if report.summary else (
        max(
            (c.priority for c in report.clusters),
            key=lambda p: (4 - _PRIORITY_ORDER[p]),
            default=ClusterPriority.NOISE,
        )
    )
    border = priority_color(overall)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()

    grid.add_row("Analyzed at", report.analyzed_at.strftime("%Y-%m-%d %H:%M:%S UTC"))
    if report.input_file:
        grid.add_row("Input file", report.input_file)
    grid.add_row("Alerts ingested", str(report.alerts_ingested))
    grid.add_row("After dedup", str(report.alerts_after_dedup))
    grid.add_row("Clusters", str(len(report.clusters)))
    grid.add_row(
        "Overall priority",
        Text(f"{overall.icon} {overall.value}", style=priority_color(overall)),
    )

    con.print(Panel(grid, title="[bold]SIFT TRIAGE REPORT[/bold]", border_style=border))


def _render_executive_summary(report: TriageReport, con: Console) -> None:
    """Print the executive summary panel if available."""
    if report.summary is None:
        return
    overall = report.summary.overall_priority
    border = priority_color(overall)
    con.print(
        Panel(
            report.summary.executive_summary,
            title="[bold]Executive Summary[/bold]",
            border_style=border,
            padding=(1, 2),
        )
    )


def _render_clusters_table(report: TriageReport, con: Console) -> None:
    """Print the clusters overview table."""
    clusters = _sorted_clusters(report.clusters)

    table = Table(
        title="Cluster Overview",
        box=box.ROUNDED,
        show_edge=True,
        pad_edge=True,
        expand=False,
    )
    table.add_column("Priority", width=14, no_wrap=True)
    table.add_column("Score", justify="right", width=7)
    table.add_column("Label", max_width=50)
    table.add_column("Alerts", justify="right", width=7)
    table.add_column("IOCs", justify="right", width=6)
    table.add_column("Hint", width=8, no_wrap=True)
    table.add_column("ATT&CK", max_width=32)
    table.add_column("Time Range", min_width=20, no_wrap=True)

    for cluster in clusters:
        row_style = "dim" if cluster.priority == ClusterPriority.NOISE else ""
        label = cluster.label[:50] if len(cluster.label) > 50 else cluster.label
        ioc_count = str(len(cluster.iocs)) if cluster.iocs else "–"
        hint = _cluster_severity_hint(cluster)
        if hint == "critical":
            hint_cell = Text("critical", style="bold red")
        elif hint == "high":
            hint_cell = Text("high", style="red")
        else:
            hint_cell = Text("–", style="dim")

        table.add_row(
            _priority_label(cluster.priority),
            f"{cluster.score:.2f}",
            label,
            str(len(cluster.alerts)),
            ioc_count,
            hint_cell,
            _fmt_techniques(cluster),
            _fmt_time_range(cluster),
            style=row_style,
        )

    con.print(table)


def _render_cluster_detail(
    cluster: Cluster,
    cluster_summary: Optional[ClusterSummary],
    con: Console,
) -> None:
    """Print a detail panel for a single cluster."""
    pri_style = priority_color(cluster.priority)
    title = (
        f"[{pri_style}]{cluster.priority.icon} {cluster.priority.value}[/{pri_style}]"
        f"  [bold]{cluster.label}[/bold]"
    )

    lines: list[str] = []

    # Narrative
    if cluster_summary and cluster_summary.narrative:
        lines.append(cluster_summary.narrative)

    # Cluster reason (if no narrative, or as supplement)
    if cluster.cluster_reason and (
        not cluster_summary or not cluster_summary.narrative
    ):
        lines.append(f"[dim]Reason: {cluster.cluster_reason}[/dim]")

    # Stats row
    conf_pct = int(cluster.confidence * 100)
    lines.append(
        f"\n[dim]Score:[/dim] [bold]{cluster.score:.1f}[/bold]  "
        f"[dim]Confidence:[/dim] [bold]{conf_pct}%[/bold]  "
        f"[dim]Alerts:[/dim] [bold]{len(cluster.alerts)}[/bold]"
    )

    # Recommendations
    if cluster_summary and cluster_summary.recommendations:
        lines.append("\n[bold cyan]Recommendations[/bold cyan]")
        for rec in cluster_summary.recommendations:
            rec_style = _RECOMMENDATION_PRIORITY_STYLE.get(rec.priority, "white")
            lines.append(
                f"  [{rec_style}][{rec.priority}][/{rec_style}]  {rec.action}"
            )
            lines.append(f"    [dim]{rec.rationale}[/dim]")

    # Top IOCs
    if cluster.iocs:
        lines.append("\n[bold cyan]IOCs[/bold cyan] [dim](top 5)[/dim]")
        for ioc in cluster.iocs[:5]:
            display = _fmt_ps_encoded(ioc) if ioc.startswith("ps_encoded:") else ioc
            lines.append(f"  [yellow]{display}[/yellow]")
        remaining = len(cluster.iocs) - 5
        if remaining > 0:
            lines.append(f"  [dim]… and {remaining} more[/dim]")

    # Top techniques
    if cluster.techniques:
        lines.append("\n[bold cyan]ATT&CK Techniques[/bold cyan] [dim](top 3)[/dim]")
        for tech in cluster.techniques[:3]:
            lines.append(
                f"  [bold]{tech.technique_id}[/bold]  {tech.technique_name}"
                f"  [dim]({tech.tactic})[/dim]"
            )

    content = "\n".join(lines)
    con.print(Panel(content, title=title, border_style=pri_style, padding=(1, 2)))


def _render_manifest_footer(report: TriageReport, con: Console) -> None:
    """Print a dim footer with pipeline manifest details."""
    if report.manifest is None:
        return
    m = report.manifest
    parts = [f"sift v{m.sift_version}", f"format: {m.input_format}"]
    if m.barb_version:
        parts.append(f"barb v{m.barb_version}")
    if m.vex_version:
        parts.append(f"vex v{m.vex_version}")
    if m.enrich_mode:
        parts.append(f"enrichment: {m.enrich_mode}")
    con.print(Text("  ".join(parts), style="dim"))
    con.print()


# ---------------------------------------------------------------------------
# Public output functions
# ---------------------------------------------------------------------------


def format_report_rich(
    report: TriageReport,
    console: Console | None = None,
) -> None:
    """Print the full triage report to console using Rich."""
    con = console or Console()

    con.print()

    # (a) Header panel
    _render_header(report, con)
    con.print()

    # (b) Executive summary
    if report.summary:
        _render_executive_summary(report, con)
        con.print()

    # (c) Clusters overview table
    if report.clusters:
        _render_clusters_table(report, con)
        con.print()

    # (d) Per-cluster detail panels
    sorted_clusters = _sorted_clusters(report.clusters)
    detail_clusters = [c for c in sorted_clusters if _should_show_detail(c, report.clusters)]

    if detail_clusters:
        for cluster in detail_clusters:
            cluster_summary = _find_cluster_summary(report, cluster.id)
            _render_cluster_detail(cluster, cluster_summary, con)
            con.print()

    # (e) Manifest footer
    _render_manifest_footer(report, con)


def format_report_console(report: TriageReport) -> None:
    """Plain text output (no Rich markup) to stdout. Pipe-friendly."""
    input_file = report.input_file or "<stdin>"
    if report.summary:
        overall = report.summary.overall_priority.value
    elif report.clusters:
        from ..models import ClusterPriority
        _order = [p.value for p in ClusterPriority]
        overall = max(
            (c.priority.value for c in report.clusters),
            key=lambda v: _order.index(v) if v in _order else -1,
            default="NOISE",
        )
    else:
        overall = "NOISE"
    print(
        f"SIFT TRIAGE REPORT  |  {report.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')}  "
        f"|  {report.alerts_ingested} alerts  |  {len(report.clusters)} clusters  "
        f"|  priority: {overall}  |  file: {input_file}"
    )
    print()

    sorted_clusters = _sorted_clusters(report.clusters)
    for cluster in sorted_clusters:
        print(
            f"{cluster.priority.value:8s} | {cluster.score:5.1f} | "
            f"{cluster.label} | {len(cluster.alerts)} alerts"
        )

    print()
