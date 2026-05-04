"""Alert chunking for large-batch triage."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sift.models import Alert, Cluster, ClusterPriority, TriageReport

if TYPE_CHECKING:
    from sift.config import ScoringConfig

_PRIORITY_ORDER: dict[ClusterPriority, int] = {
    ClusterPriority.NOISE: 0,
    ClusterPriority.LOW: 1,
    ClusterPriority.MEDIUM: 2,
    ClusterPriority.HIGH: 3,
    ClusterPriority.CRITICAL: 4,
}


def chunk_alerts(alerts: list[Alert], size: int) -> list[list[Alert]]:
    """Split alerts into chunks of `size`.

    If size <= 0 or the list fits in one chunk, return [alerts] (no chunking).
    """
    if size <= 0 or len(alerts) <= size:
        return [alerts]
    return [alerts[i : i + size] for i in range(0, len(alerts), size)]


def _merge_ioc_overlapping_clusters(
    clusters: list[Cluster],
    scoring_config: "ScoringConfig | None" = None,
) -> list[Cluster]:
    """Second-pass Union-Find merge: combine clusters that share IOCs.

    Restores cross-chunk IOC-overlap clustering that chunk boundaries prevent
    during the first-pass clustering inside each chunk.  After merging, each
    combined cluster's score and priority are re-derived from its constituent
    alerts via the prioritizer — summing pre-computed scores would double-count
    severity multipliers.
    """
    if len(clusters) <= 1:
        return clusters

    n = len(clusters)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        pi, pj = find(i), find(j)
        if pi != pj:
            parent[pj] = pi

    # Map every IOC to the cluster indices that contain it
    ioc_to_indices: dict[str, list[int]] = {}
    for idx, cluster in enumerate(clusters):
        for ioc in cluster.iocs:
            ioc_to_indices.setdefault(ioc, []).append(idx)

    # Union all clusters that share at least one IOC
    for indices in ioc_to_indices.values():
        for i in range(1, len(indices)):
            union(indices[0], indices[i])

    # Group cluster indices by their Union-Find root
    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    merged: list[Cluster] = []
    for indices in groups.values():
        if len(indices) == 1:
            merged.append(clusters[indices[0]])
            continue

        group = [clusters[i] for i in indices]
        base = max(group, key=lambda c: c.score)

        all_alerts: list[Alert] = []
        all_iocs: list[str] = []
        seen_iocs: set[str] = set()
        all_techniques = []
        seen_tech_ids: set[str] = set()
        first_seen = None
        last_seen = None

        for c in group:
            all_alerts.extend(c.alerts)
            for ioc in c.iocs:
                if ioc not in seen_iocs:
                    all_iocs.append(ioc)
                    seen_iocs.add(ioc)
            for t in (c.techniques or []):
                if t.technique_id not in seen_tech_ids:
                    all_techniques.append(t)
                    seen_tech_ids.add(t.technique_id)
            if c.first_seen and (first_seen is None or c.first_seen < first_seen):
                first_seen = c.first_seen
            if c.last_seen and (last_seen is None or c.last_seen > last_seen):
                last_seen = c.last_seen

        max_confidence = max(c.confidence for c in group)

        draft = base.model_copy(update={
            "alerts": all_alerts,
            "iocs": all_iocs,
            "techniques": all_techniques,
            "score": 0.0,
            "priority": ClusterPriority.NOISE,
            "confidence": max_confidence,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "cluster_reason": (
                f"{base.cluster_reason} [merged {len(group)} chunks by IOC overlap]"
                if base.cluster_reason else f"merged {len(group)} chunks by IOC overlap"
            ),
        })

        # Re-derive score and priority from the merged cluster's alerts so that
        # severity multipliers are applied exactly once (not summed from each chunk).
        from sift.pipeline.prioritizer import prioritize
        merged.append(prioritize(draft, scoring_config))

    merged.sort(key=lambda c: c.score, reverse=True)
    return merged


def merge_triage_reports(
    reports: list[TriageReport],
    scoring_config: "ScoringConfig | None" = None,
) -> TriageReport:
    """Merge multiple TriageReport objects into one.

    - Combines all clusters from all reports
    - Runs a second-pass IOC-overlap merge to restore cross-chunk clustering
    - Re-sorts clusters by score descending
    - Accumulates alerts_ingested and alerts_after_dedup
    - Metadata (input_file, analyzed_at, manifest, enrichment) from first report
    """
    if not reports:
        return TriageReport(
            input_file=None,
            alerts_ingested=0,
            alerts_after_dedup=0,
            clusters=[],
            analyzed_at=datetime.now(tz=timezone.utc),
        )

    if len(reports) == 1:
        return reports[0]

    all_clusters: list[Cluster] = []
    total_ingested = 0
    total_after_dedup = 0

    for report in reports:
        all_clusters.extend(report.clusters)
        total_ingested += report.alerts_ingested
        total_after_dedup += report.alerts_after_dedup

    # Second-pass: merge clusters sharing IOCs across chunk boundaries (F-02 fix)
    all_clusters = _merge_ioc_overlapping_clusters(all_clusters, scoring_config)

    first = reports[0]
    return TriageReport(
        input_file=first.input_file,
        alerts_ingested=total_ingested,
        alerts_after_dedup=total_after_dedup,
        clusters=all_clusters,
        summary=first.summary,
        enrichment=first.enrichment,
        manifest=first.manifest,
        analyzed_at=first.analyzed_at,
    )
