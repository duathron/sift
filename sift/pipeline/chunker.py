"""Alert chunking for large-batch triage."""

from __future__ import annotations

from datetime import datetime, timezone

from sift.models import Alert, Cluster, TriageReport


def chunk_alerts(alerts: list[Alert], size: int) -> list[list[Alert]]:
    """Split alerts into chunks of `size`.

    If size <= 0 or the list fits in one chunk, return [alerts] (no chunking).
    """
    if size <= 0 or len(alerts) <= size:
        return [alerts]
    return [alerts[i : i + size] for i in range(0, len(alerts), size)]


def merge_triage_reports(reports: list[TriageReport]) -> TriageReport:
    """Merge multiple TriageReport objects into one.

    - Combines all clusters from all reports
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

    all_clusters.sort(key=lambda c: c.score, reverse=True)

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
