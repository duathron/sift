"""HTML shift-handover report for sift triage results.

Produces a self-contained HTML file with embedded CSS.
Structure mirrors the sift Rich console output: cluster cards with priority,
score, alert count, IOC table, and summary narrative.

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
# Priority colour mapping (CSS class names)
# ---------------------------------------------------------------------------

_PRIORITY_CSS: dict[str, str] = {
    "CRITICAL": "priority-critical",
    "HIGH": "priority-high",
    "MEDIUM": "priority-medium",
    "LOW": "priority-low",
    "NOISE": "priority-noise",
}

_PRIORITY_ICON: dict[str, str] = {
    "CRITICAL": "!",
    "HIGH": "↑",
    "MEDIUM": "~",
    "LOW": "↓",
    "NOISE": "·",
}

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
body {
    background: #1a1a2e;
    color: #e0e0e0;
    font-family: 'Segoe UI', system-ui, monospace;
    margin: 0;
    padding: 1.5rem;
    line-height: 1.5;
}
header {
    border-bottom: 2px solid #444;
    margin-bottom: 1.5rem;
    padding-bottom: 0.75rem;
}
header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.4rem;
    color: #7eb8f7;
}
header p {
    margin: 0;
    font-size: 0.82rem;
    color: #888;
}
.meta-row {
    display: flex;
    gap: 2rem;
    margin-top: 0.5rem;
    font-size: 0.82rem;
    color: #aaa;
}
.cluster-card {
    border: 1px solid #333;
    border-radius: 6px;
    margin-bottom: 1.2rem;
    overflow: hidden;
}
.cluster-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.6rem 1rem;
    background: #16213e;
}
.cluster-label {
    font-weight: bold;
    font-size: 1rem;
    flex: 1;
}
.cluster-meta {
    font-size: 0.8rem;
    color: #aaa;
}
.cluster-body {
    padding: 0.75rem 1rem;
}
.priority-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: bold;
    font-family: monospace;
}
.priority-critical { background: #7f0000; color: #ffcccc; }
.priority-high     { background: #5c1a00; color: #ffddbb; }
.priority-medium   { background: #4a3800; color: #fff0a0; }
.priority-low      { background: #003340; color: #a0e0ff; }
.priority-noise    { background: #2a2a2a; color: #999; }
.ioc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
    margin-top: 0.5rem;
}
.ioc-table th {
    text-align: left;
    padding: 0.25rem 0.5rem;
    background: #222;
    color: #7eb8f7;
    border-bottom: 1px solid #444;
}
.ioc-table td {
    padding: 0.2rem 0.5rem;
    border-bottom: 1px solid #2a2a2a;
    font-family: monospace;
    word-break: break-all;
}
.ioc-table tr:hover { background: #1e1e1e; }
.alert-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
    margin-top: 0.5rem;
}
.alert-table th {
    text-align: left;
    padding: 0.25rem 0.5rem;
    background: #222;
    color: #7eb8f7;
    border-bottom: 1px solid #444;
}
.alert-table td {
    padding: 0.2rem 0.5rem;
    border-bottom: 1px solid #2a2a2a;
}
.section-title {
    font-size: 0.82rem;
    color: #7eb8f7;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0.75rem 0 0.3rem;
    font-weight: bold;
}
.narrative {
    font-size: 0.88rem;
    color: #ccc;
    background: #111827;
    padding: 0.5rem 0.75rem;
    border-left: 3px solid #3a5a7a;
    margin: 0.5rem 0;
}
footer {
    margin-top: 2rem;
    padding-top: 0.5rem;
    border-top: 1px solid #333;
    font-size: 0.78rem;
    color: #666;
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _esc(text: str) -> str:
    """Minimal HTML escaping for safe embedding of arbitrary text."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _priority_badge(priority_value: str) -> str:
    css = _PRIORITY_CSS.get(priority_value, "priority-noise")
    icon = _PRIORITY_ICON.get(priority_value, "·")
    return f'<span class="priority-badge {css}">{icon} {_esc(priority_value)}</span>'


def _render_cluster(cluster: "Cluster") -> str:
    priority_val = cluster.priority.value if hasattr(cluster.priority, "value") else str(cluster.priority)
    parts: list[str] = []

    # Header
    alert_count = len(cluster.alerts)
    score_str = f"{cluster.score:.0f}"
    parts.append('<div class="cluster-card">')
    parts.append('<div class="cluster-header">')
    parts.append(_priority_badge(priority_val))
    parts.append(f'<span class="cluster-label">{_esc(cluster.label)}</span>')
    parts.append(
        f'<span class="cluster-meta">'
        f"score {score_str} &bull; {alert_count} alert{'s' if alert_count != 1 else ''}"
        f"</span>"
    )
    parts.append("</div>")  # cluster-header

    parts.append('<div class="cluster-body">')

    # Summary narrative (if present)
    if cluster.cluster_reason:
        parts.append(f'<div class="narrative">{_esc(cluster.cluster_reason)}</div>')

    # Techniques
    if cluster.techniques:
        tids = []
        for t in cluster.techniques:
            tid = getattr(t, "technique_id", None) or str(t)
            tname = getattr(t, "technique_name", "")
            tids.append(f"{_esc(tid)}" + (f" — {_esc(tname)}" if tname else ""))
        parts.append('<p class="section-title">ATT&amp;CK Techniques</p>')
        parts.append("<ul style='margin:0 0 0.5rem 1rem; padding:0; font-size:0.82rem;'>")
        for t in tids:
            parts.append(f"<li>{t}</li>")
        parts.append("</ul>")

    # IOC table
    if cluster.iocs:
        parts.append('<p class="section-title">Indicators of Compromise</p>')
        parts.append('<table class="ioc-table">')
        parts.append("<thead><tr><th>IOC Value</th><th>Type</th></tr></thead>")
        parts.append("<tbody>")

        # Build type lookup from iocs_typed if available
        type_map: dict[str, str] = {}
        for ioc_obj in cluster.iocs_typed or []:
            type_map[ioc_obj.value] = ioc_obj.type

        for ioc_val in cluster.iocs:
            ioc_type = type_map.get(ioc_val, "—")
            parts.append(f"<tr><td>{_esc(ioc_val)}</td><td>{_esc(ioc_type)}</td></tr>")
        parts.append("</tbody></table>")

    # Alert table (compact)
    if cluster.alerts:
        parts.append('<p class="section-title">Alerts</p>')
        parts.append('<table class="alert-table">')
        parts.append(
            "<thead><tr><th>Severity</th><th>Title</th><th>Source IP</th><th>User</th><th>Timestamp</th></tr></thead>"
        )
        parts.append("<tbody>")
        for alert in cluster.alerts:
            sev = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
            ts = alert.timestamp.strftime("%Y-%m-%d %H:%M") if alert.timestamp else "—"
            parts.append(
                "<tr>"
                f"<td>{_esc(sev)}</td>"
                f"<td>{_esc(alert.title)}</td>"
                f"<td>{_esc(str(alert.source_ip or '—'))}</td>"
                f"<td>{_esc(str(alert.user or '—'))}</td>"
                f"<td>{_esc(ts)}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    parts.append("</div>")  # cluster-body
    parts.append("</div>")  # cluster-card
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_html_report(report: "TriageReport") -> str:
    """Render a TriageReport as a self-contained HTML shift-handover document.

    The report object is rendered verbatim — redaction must be applied
    at the model layer before calling this function (sift's standard
    pipeline applies config.redaction automatically).

    Returns the complete HTML string (no file I/O).
    """
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    analyzed_at = report.analyzed_at.strftime("%Y-%m-%d %H:%M UTC") if report.analyzed_at else ts
    input_name = _esc(report.input_file or "unknown")

    cluster_count = len(report.clusters)
    alert_count = report.alerts_ingested

    # Sort clusters by priority for display (critical first)
    _ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NOISE": 4}
    sorted_clusters = sorted(
        report.clusters,
        key=lambda c: _ORDER.get(c.priority.value if hasattr(c.priority, "value") else str(c.priority), 5),
    )

    # Render cluster cards
    cluster_html = "\n".join(_render_cluster(c) for c in sorted_clusters)

    # Summary section (AI or template narrative)
    summary_html = ""
    if report.summary:
        s = report.summary
        overall = s.overall_priority.value if hasattr(s.overall_priority, "value") else str(s.overall_priority)
        summary_html = (
            '<section style="margin-bottom:1.5rem;">'
            '<h2 style="font-size:1rem; color:#7eb8f7;">Executive Summary</h2>'
            f'<div class="narrative">{_esc(s.executive_summary)}</div>'
            f'<p style="font-size:0.8rem; color:#888;">Overall priority: '
            f"{_priority_badge(overall)} &bull; "
            f"Provider: {_esc(s.provider)}</p>"
            "</section>"
        )

    html = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>sift Shift-Handover Report — {input_name}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "<header>\n"
        f"<h1>sift Shift-Handover Report</h1>\n"
        '<div class="meta-row">'
        f"<span>Input: {input_name}</span>"
        f"<span>Analyzed: {_esc(analyzed_at)}</span>"
        f"<span>Generated: {_esc(ts)}</span>"
        f"<span>{cluster_count} cluster{'s' if cluster_count != 1 else ''} &bull; "
        f"{alert_count} alert{'s' if alert_count != 1 else ''} ingested</span>"
        f"<span>sift v{_esc(__version__)}</span>"
        "</div>\n"
        "</header>\n"
        f"{summary_html}"
        '<section id="clusters">\n'
        f"{cluster_html}\n"
        "</section>\n"
        "<footer>\n"
        f"<p>sift v{_esc(__version__)} &mdash; "
        "Shift-handover reports respect configured field redaction. "
        f"Generated {_esc(ts)}.</p>\n"
        "</footer>\n"
        "</body>\n"
        "</html>\n"
    )
    return html
