"""Map a TriageReport + Cluster into a TicketDraft."""

from __future__ import annotations

from datetime import datetime, timezone

from sift import __version__
from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    ClusterSummary,
    TriageReport,
)
from sift.ticketing.protocol import TicketDraft

_PRIORITY_MAP: dict[ClusterPriority, str] = {
    ClusterPriority.CRITICAL: "IMMEDIATE",
    ClusterPriority.HIGH: "WITHIN_1H",
    ClusterPriority.MEDIUM: "WITHIN_24H",
    ClusterPriority.LOW: "MONITOR",
    ClusterPriority.NOISE: "MONITOR",
}

_TIMELINE_MAX = 10
_TITLE_MAX = 80


def report_to_draft(report: TriageReport, cluster: Cluster | None = None) -> TicketDraft:
    """Build a TicketDraft from a TriageReport for one cluster.

    If *cluster* is None the highest-priority cluster in the report is used.
    Raises ValueError when the report has no clusters.
    """
    target = cluster or _top_cluster(report)
    if target is None:
        raise ValueError("report has no clusters — cannot create ticket")

    sev = _top_severity(target)
    cluster_summary = _find_cluster_summary(report, target.id)

    return TicketDraft(
        title=_build_title(target, sev),
        summary=_build_summary(target, cluster_summary),
        severity=sev,
        priority=_PRIORITY_MAP.get(target.priority, "WITHIN_24H"),
        confidence=target.confidence,
        timeline=_build_timeline(target),
        iocs=list(target.iocs),
        technique_ids=_extract_technique_ids(target),
        recommendations=_extract_recommendations(cluster_summary),
        evidence={
            "cluster_id": target.id,
            "cluster_label": target.label,
            "alert_count": len(target.alerts),
            "score": target.score,
            "cluster_reason": target.cluster_reason,
            "first_seen": target.first_seen.isoformat() if target.first_seen else None,
            "last_seen": target.last_seen.isoformat() if target.last_seen else None,
        },
        source_file=report.input_file,
        generated_at=datetime.now(tz=timezone.utc),
        sift_version=__version__,
    )


def top_clusters_for_ticket(
    report: TriageReport,
    priorities: tuple[str, ...] = ("CRITICAL", "HIGH"),
) -> list[Cluster]:
    """Return clusters whose priority is in *priorities*, sorted by score desc."""
    return sorted(
        [c for c in report.clusters if c.priority.value in priorities],
        key=lambda c: c.score,
        reverse=True,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _top_cluster(report: TriageReport) -> Cluster | None:
    if not report.clusters:
        return None
    _order = {p: i for i, p in enumerate([
        ClusterPriority.CRITICAL, ClusterPriority.HIGH,
        ClusterPriority.MEDIUM, ClusterPriority.LOW, ClusterPriority.NOISE,
    ])}
    return min(report.clusters, key=lambda c: (_order.get(c.priority, 99), -c.score))


def _top_severity(cluster: Cluster) -> str:
    if not cluster.alerts:
        return AlertSeverity.MEDIUM.value
    return max(cluster.alerts, key=lambda a: a.severity.score).severity.value


def _build_title(cluster: Cluster, severity: str) -> str:
    label = cluster.label
    if len(label) > _TITLE_MAX - 20:
        label = label[:_TITLE_MAX - 23] + "..."
    return f"[sift] {severity} | {label}"


def _build_summary(cluster: Cluster, cs: ClusterSummary | None) -> str:
    if cs and cs.narrative:
        return cs.narrative
    high_crit = sum(
        1 for a in cluster.alerts
        if a.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)
    )
    return (
        f"Cluster '{cluster.label}' contains {len(cluster.alerts)} alert(s) "
        f"({high_crit} HIGH/CRITICAL) with priority {cluster.priority.value}. "
        f"Clustering confidence: {cluster.confidence:.0%}. "
        "Review the timeline and IOCs for further context."
    )


def _build_timeline(cluster: Cluster) -> list[str]:
    _epoch = datetime.min.replace(tzinfo=timezone.utc)
    sorted_alerts = sorted(
        cluster.alerts,
        key=lambda a: a.timestamp if a.timestamp else _epoch,
    )
    lines: list[str] = []
    for alert in sorted_alerts[:_TIMELINE_MAX]:
        ts = (
            alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            if alert.timestamp
            else "unknown time"
        )
        lines.append(f"[{ts}] [{alert.severity.value}] {alert.title}")
    remaining = len(cluster.alerts) - _TIMELINE_MAX
    if remaining > 0:
        lines.append(f"... and {remaining} more alert(s)")
    return lines


def _extract_technique_ids(cluster: Cluster) -> list[str]:
    ids: list[str] = []
    for t in cluster.techniques:
        # TechniqueRef objects carry .technique_id; guard against bare strings
        # in test fixtures that may bypass Pydantic coercion.
        if hasattr(t, "technique_id"):
            ids.append(t.technique_id)
        elif isinstance(t, str):
            ids.append(t)
    return list(dict.fromkeys(ids))  # deduplicate, preserve order


def _find_cluster_summary(report: TriageReport, cluster_id: str) -> ClusterSummary | None:
    if report.summary is None:
        return None
    for cs in report.summary.cluster_summaries:
        if cs.cluster_id == cluster_id:
            return cs
    return None


def _extract_recommendations(cs: ClusterSummary | None) -> list[str]:
    if cs is None:
        return []
    return [r.action for r in cs.recommendations]
