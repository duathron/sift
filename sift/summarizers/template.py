"""Template-based summarizer — no LLM, fully deterministic.

Produces concise, rule-driven narratives and recommendations from a
:class:`~sift.models.TriageReport` without any external API calls.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from sift.models import (
    Cluster,
    ClusterPriority,
    ClusterSummary,
    Recommendation,
    SummaryResult,
    TriageReport,
)


# ---------------------------------------------------------------------------
# Priority ordering (used for max() comparisons)
# ---------------------------------------------------------------------------

_PRIORITY_ORDER: dict[ClusterPriority, int] = {
    ClusterPriority.NOISE: 0,
    ClusterPriority.LOW: 1,
    ClusterPriority.MEDIUM: 2,
    ClusterPriority.HIGH: 3,
    ClusterPriority.CRITICAL: 4,
}


def _higher_priority(a: ClusterPriority, b: ClusterPriority) -> ClusterPriority:
    """Return whichever of *a* or *b* has higher severity."""
    return a if _PRIORITY_ORDER[a] >= _PRIORITY_ORDER[b] else b


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _dominant_severity_label(cluster: Cluster) -> str:
    """Return the most common alert severity value in *cluster* as a string."""
    if not cluster.alerts:
        return "unknown"
    counts: Counter[str] = Counter(a.severity.value for a in cluster.alerts)
    return counts.most_common(1)[0][0]


def _ioc_summary(cluster: Cluster) -> str:
    """One-phrase IOC summary for a cluster narrative."""
    if not cluster.iocs:
        return "No IOCs extracted"
    first = cluster.iocs[0]
    n = len(cluster.iocs)
    return f"Involves {n} IOC(s) including {first}"


def _technique_summary(cluster: Cluster) -> str:
    """One-phrase ATT&CK technique summary for a cluster narrative."""
    if not cluster.techniques:
        return "No ATT&CK mapping"
    ids = ", ".join(t.technique_id for t in cluster.techniques)
    return f"ATT&CK: {ids}"


def _build_narrative(cluster: Cluster) -> str:
    """Compose the 1-sentence deterministic narrative for *cluster*."""
    count = len(cluster.alerts)
    sev_label = _dominant_severity_label(cluster)
    reason = cluster.cluster_reason or "shared attributes"
    ioc_part = _ioc_summary(cluster)
    tech_part = _technique_summary(cluster)
    return (
        f"{count} {sev_label} alert(s) grouped by {reason}. "
        f"{ioc_part}. {tech_part}."
    )


def _build_recommendations(cluster: Cluster) -> list[Recommendation]:
    """Return 1–3 rule-based recommendations for *cluster*."""
    p = cluster.priority

    if p == ClusterPriority.CRITICAL:
        return [
            Recommendation(
                action="Isolate affected hosts immediately",
                priority="IMMEDIATE",
                rationale="Critical-priority cluster indicates active or high-confidence threat.",
            ),
            Recommendation(
                action="Block all IOCs at perimeter",
                priority="IMMEDIATE",
                rationale="Prevent lateral movement or exfiltration while investigation proceeds.",
            ),
        ]

    if p == ClusterPriority.HIGH:
        return [
            Recommendation(
                action="Investigate affected systems",
                priority="WITHIN_1H",
                rationale="High-priority cluster warrants prompt analyst review to confirm or deny compromise.",
            ),
            Recommendation(
                action="Block top IOCs",
                priority="WITHIN_1H",
                rationale="Reduce attack surface by blocking the most prominent indicators in this cluster.",
            ),
        ]

    if p == ClusterPriority.MEDIUM:
        return [
            Recommendation(
                action="Review and validate alerts",
                priority="WITHIN_24H",
                rationale="Medium-priority cluster may represent suspicious activity requiring analyst triage.",
            ),
        ]

    # LOW or NOISE
    return [
        Recommendation(
            action="Monitor for escalation",
            priority="MONITOR",
            rationale="Low-confidence or low-severity cluster; re-evaluate if new alerts arrive.",
        ),
    ]


# ---------------------------------------------------------------------------
# TemplateSummarizer
# ---------------------------------------------------------------------------

class TemplateSummarizer:
    """Deterministic, no-LLM summarizer implementing :class:`~sift.summarizers.protocol.SummarizerProtocol`.

    All output is produced from hard-coded templates and rule-based logic,
    making this summarizer suitable for air-gapped or offline environments and
    as a reliable fallback when LLM providers are unavailable.
    """

    @property
    def name(self) -> str:
        """Identifier reported in :attr:`~sift.models.SummaryResult.provider`."""
        return "template"

    def summarize(self, report: TriageReport) -> SummaryResult:
        """Generate a :class:`~sift.models.SummaryResult` from *report*.

        The method is fully deterministic: given the same input it will always
        produce the same output.

        Args:
            report: A completed :class:`~sift.models.TriageReport` with at
                least the ``alerts_ingested``, ``alerts_after_dedup``, and
                ``clusters`` fields populated.

        Returns:
            A :class:`~sift.models.SummaryResult` with an executive summary,
            per-cluster narratives (non-NOISE only), rule-based recommendations,
            and an ``overall_priority`` derived from the highest cluster
            priority in the report.
        """
        clusters = report.clusters

        # ------------------------------------------------------------------ #
        # Executive summary
        # ------------------------------------------------------------------ #
        n = report.alerts_ingested
        dedup_count = report.alerts_after_dedup
        cluster_count = len(clusters)
        critical_count = sum(
            1 for c in clusters if c.priority == ClusterPriority.CRITICAL
        )

        if critical_count > 0:
            exec_summary = (
                f"Processed {n} alert(s) ({dedup_count} after deduplication), "
                f"grouped into {cluster_count} cluster(s). "
                f"{critical_count} cluster(s) require immediate attention."
            )
        else:
            exec_summary = (
                f"Processed {n} alert(s) ({dedup_count} after deduplication), "
                f"grouped into {cluster_count} cluster(s). "
                f"No clusters require immediate attention."
            )

        # ------------------------------------------------------------------ #
        # Per-cluster summaries (skip pure NOISE clusters)
        # ------------------------------------------------------------------ #
        cluster_summaries: list[ClusterSummary] = []
        for cluster in clusters:
            if cluster.priority == ClusterPriority.NOISE:
                continue
            cluster_summaries.append(
                ClusterSummary(
                    cluster_id=cluster.id,
                    narrative=_build_narrative(cluster),
                    recommendations=_build_recommendations(cluster),
                )
            )

        # ------------------------------------------------------------------ #
        # Overall priority — highest across non-NOISE clusters
        # ------------------------------------------------------------------ #
        overall: ClusterPriority = ClusterPriority.NOISE
        for cluster in clusters:
            if cluster.priority != ClusterPriority.NOISE:
                overall = _higher_priority(overall, cluster.priority)

        return SummaryResult(
            executive_summary=exec_summary,
            cluster_summaries=cluster_summaries,
            overall_priority=overall,
            provider=self.name,
            generated_at=datetime.now(tz=timezone.utc),
        )
