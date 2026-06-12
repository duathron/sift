"""Markdown shift-handover report for sift triage results.

Produces a Markdown document suitable for pasting into Jira/Confluence,
attaching to a ticket, or committing to a shift-handover repository.

Structure: title, metadata, executive summary (if present), then one
section per cluster with priority, alert table, and IOC table.

Redaction is respected at the model layer — fields already redacted on Alert
and Cluster objects are rendered as-is ([REDACTED]); this module never
re-surfaces raw data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sift.models import Cluster, TriageReport

from sift import __version__

# ---------------------------------------------------------------------------
# Priority icons (plain text, no terminal escape codes)
# ---------------------------------------------------------------------------

_PRIORITY_ICON: dict[str, str] = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "NOISE": "⚪ NOISE",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _md_escape(text: str) -> str:
    """Escape Markdown special characters in inline text."""
    # Escape characters that affect Markdown formatting
    for ch in ("|", "`", "*", "_", "[", "]", "<", ">", "#", "\\"):
        text = text.replace(ch, f"\\{ch}")
    return text


def _priority_label(priority_value: str) -> str:
    return _PRIORITY_ICON.get(priority_value, priority_value)


def _render_cluster(cluster: "Cluster") -> str:
    priority_val = cluster.priority.value if hasattr(cluster.priority, "value") else str(cluster.priority)
    lines: list[str] = []

    alert_count = len(cluster.alerts)
    score_str = f"{cluster.score:.0f}"

    lines.append(f"### {_md_escape(cluster.label)}")
    lines.append("")
    lines.append(
        f"**Priority:** {_priority_label(priority_val)} &nbsp;|&nbsp; "
        f"**Score:** {score_str} &nbsp;|&nbsp; "
        f"**Alerts:** {alert_count}"
    )
    lines.append("")

    # Cluster reason / narrative
    if cluster.cluster_reason:
        lines.append(f"> {_md_escape(cluster.cluster_reason)}")
        lines.append("")

    # Techniques
    if cluster.techniques:
        lines.append("**ATT&CK Techniques:**")
        for t in cluster.techniques:
            tid = getattr(t, "technique_id", None) or str(t)
            tname = getattr(t, "technique_name", "")
            tactic = getattr(t, "tactic", "")
            suffix = ""
            if tname:
                suffix += f" — {_md_escape(tname)}"
            if tactic:
                suffix += f" ({_md_escape(tactic)})"
            lines.append(f"- `{_md_escape(tid)}`{suffix}")
        lines.append("")

    # IOC table
    if cluster.iocs:
        # Build type lookup from iocs_typed if available
        type_map: dict[str, str] = {}
        for ioc_obj in cluster.iocs_typed or []:
            type_map[ioc_obj.value] = ioc_obj.type

        lines.append("**Indicators of Compromise:**")
        lines.append("")
        lines.append("| IOC Value | Type |")
        lines.append("|-----------|------|")
        for ioc_val in cluster.iocs:
            ioc_type = type_map.get(ioc_val, "—")
            lines.append(f"| `{_md_escape(ioc_val)}` | {_md_escape(ioc_type)} |")
        lines.append("")

    # Alert table
    if cluster.alerts:
        lines.append("**Alerts:**")
        lines.append("")
        lines.append("| Severity | Title | Source IP | User | Timestamp |")
        lines.append("|----------|-------|-----------|------|-----------|")
        for alert in cluster.alerts:
            sev = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
            ts = alert.timestamp.strftime("%Y-%m-%d %H:%M") if alert.timestamp else "—"
            lines.append(
                f"| {_md_escape(sev)}"
                f" | {_md_escape(alert.title)}"
                f" | {_md_escape(str(alert.source_ip or '—'))}"
                f" | {_md_escape(str(alert.user or '—'))}"
                f" | {_md_escape(ts)}"
                " |"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_md_report(report: "TriageReport") -> str:
    """Render a TriageReport as a Markdown shift-handover document.

    The report object is rendered verbatim — redaction must be applied
    at the model layer before calling this function (sift's standard
    pipeline applies config.redaction automatically).

    Returns the complete Markdown string (no file I/O).
    """
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    analyzed_at = report.analyzed_at.strftime("%Y-%m-%d %H:%M UTC") if report.analyzed_at else ts
    input_name = report.input_file or "unknown"

    cluster_count = len(report.clusters)
    alert_count = report.alerts_ingested

    lines: list[str] = []

    # Title
    lines.append("# sift Shift-Handover Report")
    lines.append("")

    # Metadata table
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Input | `{_md_escape(input_name)}` |")
    lines.append(f"| Analyzed | {_md_escape(analyzed_at)} |")
    lines.append(f"| Generated | {_md_escape(ts)} |")
    lines.append(f"| Clusters | {cluster_count} |")
    lines.append(f"| Alerts ingested | {alert_count} |")
    lines.append(f"| Alerts after dedup | {report.alerts_after_dedup} |")
    lines.append(f"| sift version | {_md_escape(__version__)} |")
    lines.append("")

    # Executive summary
    if report.summary:
        s = report.summary
        overall = s.overall_priority.value if hasattr(s.overall_priority, "value") else str(s.overall_priority)
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"**Overall Priority:** {_priority_label(overall)}")
        lines.append("")
        lines.append(s.executive_summary)
        lines.append("")

    # Clusters
    lines.append("## Clusters")
    lines.append("")

    # Sort by priority (critical first)
    _ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NOISE": 4}
    sorted_clusters = sorted(
        report.clusters,
        key=lambda c: _ORDER.get(c.priority.value if hasattr(c.priority, "value") else str(c.priority), 5),
    )

    for cluster in sorted_clusters:
        lines.append(_render_cluster(cluster))
        lines.append("---")
        lines.append("")

    # Footer
    lines.append(f"*Generated by sift v{__version__} — Shift-handover reports respect configured field redaction.*")

    return "\n".join(lines)
