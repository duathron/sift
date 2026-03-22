"""Alert clustering pipeline for sift.

Groups related alerts into Cluster objects using a multi-pass greedy strategy:

  Pass 1 — IOC overlap      : alerts sharing ≥1 IOC are merged via Union-Find.
  Pass 2 — Category + time  : same category AND within time_window_minutes.
  Pass 3 — IP-pair + time   : matching (source_ip, dest_ip) AND within time window.
  Pass 4 — Singletons       : any ungrouped alert becomes its own cluster.

Priority is left as ClusterPriority.MEDIUM for all clusters — downstream
prioritizer.py is responsible for the final assignment.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Optional

from sift.config import ClusteringConfig
from sift.models import Alert, Cluster, ClusterPriority, TechniqueRef

# ---------------------------------------------------------------------------
# Union-Find (Disjoint Set Union)
# ---------------------------------------------------------------------------

class _UnionFind:
    """Path-compressed, union-by-rank disjoint set."""

    def __init__(self, n: int) -> None:
        self._parent: list[int] = list(range(n))
        self._rank: list[int] = [0] * n

    def find(self, x: int) -> int:
        """Return the root representative of *x* with path compression."""
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]  # path halving
            x = self._parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        """Merge the sets containing *x* and *y*."""
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def same(self, x: int, y: int) -> bool:
        """Return True if *x* and *y* belong to the same set."""
        return self.find(x) == self.find(y)


# ---------------------------------------------------------------------------
# Label helpers
# ---------------------------------------------------------------------------

_LABEL_MAX_LEN = 60


def _singleton_label(alert: Alert) -> str:
    """Truncate alert title to _LABEL_MAX_LEN chars for singleton clusters."""
    title = alert.title or "(no title)"
    return title[:_LABEL_MAX_LEN]


def _ioc_cluster_label(shared_iocs: list[str]) -> str:
    """Return a human-readable label for an IOC-based cluster."""
    if len(shared_iocs) == 1:
        return f"IOC Cluster: {shared_iocs[0]}"
    return f"IOC Campaign ({len(shared_iocs)} IOCs)"


def _category_cluster_label(category: str, count: int) -> str:
    return f"{category} – {count} alerts"


def _ip_pair_cluster_label(src: str, dest: str, count: int) -> str:
    return f"{src} → {dest} ({count} alerts)"


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def _aggregate_iocs(alerts: list[Alert]) -> list[str]:
    """Return a sorted, deduplicated list of all IOCs across *alerts*."""
    seen: set[str] = set()
    for alert in alerts:
        seen.update(alert.iocs)
    return sorted(seen)


def _aggregate_techniques(alerts: list[Alert]) -> list[TechniqueRef]:
    """Return deduplicated TechniqueRefs (by technique_id) across *alerts*.

    Alerts only carry raw ``technique_ids`` strings; we build minimal
    TechniqueRef objects with the ID and leave name/tactic empty so that
    downstream enrichment (e.g. a MITRE lookup) can fill them in later.
    """
    seen_ids: set[str] = set()
    refs: list[TechniqueRef] = []
    for alert in alerts:
        for tid in alert.technique_ids:
            if tid not in seen_ids:
                seen_ids.add(tid)
                refs.append(TechniqueRef(technique_id=tid, technique_name="", tactic=""))
    return refs


def _time_bounds(alerts: list[Alert]) -> tuple[Optional[datetime], Optional[datetime]]:
    """Return (first_seen, last_seen) from alert timestamps, ignoring None values."""
    timestamps = [a.timestamp for a in alerts if a.timestamp is not None]
    if not timestamps:
        return None, None
    return min(timestamps), max(timestamps)


def _cluster_score(alerts: list[Alert]) -> float:
    """Sum of member alert severity scores."""
    return float(sum(a.severity.score for a in alerts))


# ---------------------------------------------------------------------------
# Time-window predicate
# ---------------------------------------------------------------------------

def _within_window(a: Alert, b: Alert, window: timedelta) -> bool:
    """Return True if both alerts have timestamps and are within *window* of each other."""
    if a.timestamp is None or b.timestamp is None:
        return False
    return abs((a.timestamp - b.timestamp).total_seconds()) <= window.total_seconds()


# ---------------------------------------------------------------------------
# Cluster builder
# ---------------------------------------------------------------------------

def _build_cluster(
    cluster_id: str,
    alerts: list[Alert],
    label: str,
    confidence: float,
    cluster_reason: str,
) -> Cluster:
    """Construct a Cluster from a list of member alerts."""
    first_seen, last_seen = _time_bounds(alerts)
    return Cluster(
        id=cluster_id,
        label=label,
        alerts=alerts,
        priority=ClusterPriority.MEDIUM,  # set by prioritizer.py
        score=_cluster_score(alerts),
        confidence=confidence,
        techniques=_aggregate_techniques(alerts),
        iocs=_aggregate_iocs(alerts),
        first_seen=first_seen,
        last_seen=last_seen,
        cluster_reason=cluster_reason,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def cluster_alerts(
    alerts: list[Alert],
    config: ClusteringConfig | None = None,
) -> list[Cluster]:
    """Group *alerts* into Cluster objects using a multi-pass greedy strategy.

    Passes
    ------
    1. IOC overlap         — alerts sharing ≥1 IOC (Union-Find merge).
    2. Category + time     — same ``category`` within ``time_window_minutes``.
    3. Source/dest IP pair — same ``(source_ip, dest_ip)`` within time window.
    4. Singletons          — any remaining ungrouped alert.

    Parameters
    ----------
    alerts:
        Normalized alerts to cluster.  May be an empty list.
    config:
        Clustering configuration.  Defaults to ``ClusteringConfig()`` if omitted.

    Returns
    -------
    list[Cluster]
        Clusters sorted by ``score`` descending (highest priority first).
        All clusters carry ``ClusterPriority.MEDIUM``; call ``prioritizer.py``
        afterwards to assign the real priority.
    """
    if not alerts:
        return []

    cfg = config or ClusteringConfig()
    window = timedelta(minutes=cfg.time_window_minutes)
    n = len(alerts)
    uf = _UnionFind(n)


    # -----------------------------------------------------------------------
    # Pass 1: IOC overlap
    # -----------------------------------------------------------------------
    # Build a map from each IOC to the list of alert indices that carry it.
    ioc_to_indices: dict[str, list[int]] = {}
    for i, alert in enumerate(alerts):
        for ioc in alert.iocs:
            ioc_to_indices.setdefault(ioc, []).append(i)

    for indices in ioc_to_indices.values():
        if len(indices) < 2:
            continue
        root = indices[0]
        for j in indices[1:]:
            uf.union(root, j)

    # -----------------------------------------------------------------------
    # Pass 2: Same category + time window
    # -----------------------------------------------------------------------
    # Group alerts by category first to limit the quadratic comparison space.
    category_groups: dict[str, list[int]] = {}
    for i, alert in enumerate(alerts):
        if alert.category:
            category_groups.setdefault(alert.category, []).append(i)

    for indices in category_groups.values():
        if len(indices) < 2:
            continue
        # O(m²) within each category bucket — acceptable for typical batch sizes.
        for a_pos in range(len(indices)):
            for b_pos in range(a_pos + 1, len(indices)):
                i, j = indices[a_pos], indices[b_pos]
                if not uf.same(i, j) and _within_window(alerts[i], alerts[j], window):
                    uf.union(i, j)

    # -----------------------------------------------------------------------
    # Pass 3: Same (source_ip, dest_ip) pair + time window
    # -----------------------------------------------------------------------
    ip_pair_groups: dict[tuple[str, str], list[int]] = {}
    for i, alert in enumerate(alerts):
        src = alert.source_ip
        dst = alert.dest_ip
        if src and dst:
            ip_pair_groups.setdefault((src, dst), []).append(i)

    for indices in ip_pair_groups.values():
        if len(indices) < 2:
            continue
        for a_pos in range(len(indices)):
            for b_pos in range(a_pos + 1, len(indices)):
                i, j = indices[a_pos], indices[b_pos]
                if not uf.same(i, j) and _within_window(alerts[i], alerts[j], window):
                    uf.union(i, j)

    # -----------------------------------------------------------------------
    # Collect groups: map root → member alert indices
    # -----------------------------------------------------------------------
    root_to_members: dict[int, list[int]] = {}
    for i in range(n):
        root = uf.find(i)
        root_to_members.setdefault(root, []).append(i)

    # -----------------------------------------------------------------------
    # Build Cluster objects
    # -----------------------------------------------------------------------
    clusters: list[Cluster] = []

    for root, member_indices in root_to_members.items():
        member_alerts = [alerts[i] for i in member_indices]
        is_singleton = len(member_alerts) == 1

        if is_singleton:
            # Pass 4: singleton
            alert = member_alerts[0]
            cluster = _build_cluster(
                cluster_id=str(uuid.uuid4()),
                alerts=member_alerts,
                label=_singleton_label(alert),
                confidence=1.0,
                cluster_reason="singleton",
            )
            clusters.append(cluster)
            continue

        # Determine the dominant clustering signal for this group.
        # Priority: IOC > IP-pair > category.
        shared_iocs = _find_shared_iocs(member_alerts)
        if shared_iocs:
            label = _ioc_cluster_label(shared_iocs)
            confidence = 0.95
            reason = f"IOC overlap: {', '.join(shared_iocs[:3])}" + (
                f" (+{len(shared_iocs) - 3} more)" if len(shared_iocs) > 3 else ""
            )
        else:
            dominant_pair = _find_dominant_ip_pair(member_alerts)
            if dominant_pair:
                src, dst = dominant_pair
                label = _ip_pair_cluster_label(src, dst, len(member_alerts))
                confidence = 0.80
                reason = f"source/dest IP pair: {src} → {dst}"
            else:
                category = _find_dominant_category(member_alerts)
                cat_label = category or "Mixed"
                label = _category_cluster_label(cat_label, len(member_alerts))
                confidence = 0.75
                reason = f"same category within {cfg.time_window_minutes}m: {cat_label}"

        cluster = _build_cluster(
            cluster_id=str(uuid.uuid4()),
            alerts=member_alerts,
            label=label,
            confidence=confidence,
            cluster_reason=reason,
        )
        clusters.append(cluster)

    # -----------------------------------------------------------------------
    # Sort by score descending
    # -----------------------------------------------------------------------
    clusters.sort(key=lambda c: c.score, reverse=True)
    return clusters


# ---------------------------------------------------------------------------
# Private helpers for label / reason resolution
# ---------------------------------------------------------------------------

def _find_shared_iocs(alerts: list[Alert]) -> list[str]:
    """Return sorted list of IOCs present in more than one alert in the group."""
    ioc_count: dict[str, int] = {}
    for alert in alerts:
        for ioc in set(alert.iocs):  # deduplicate per alert
            ioc_count[ioc] = ioc_count.get(ioc, 0) + 1
    return sorted(ioc for ioc, cnt in ioc_count.items() if cnt > 1)


def _find_dominant_ip_pair(alerts: list[Alert]) -> Optional[tuple[str, str]]:
    """Return the most common (source_ip, dest_ip) pair, or None."""
    pair_count: dict[tuple[str, str], int] = {}
    for alert in alerts:
        if alert.source_ip and alert.dest_ip:
            pair = (alert.source_ip, alert.dest_ip)
            pair_count[pair] = pair_count.get(pair, 0) + 1
    if not pair_count:
        return None
    return max(pair_count, key=lambda p: pair_count[p])


def _find_dominant_category(alerts: list[Alert]) -> Optional[str]:
    """Return the most common category among *alerts*, or None."""
    cat_count: dict[str, int] = {}
    for alert in alerts:
        if alert.category:
            cat_count[alert.category] = cat_count.get(alert.category, 0) + 1
    if not cat_count:
        return None
    return max(cat_count, key=lambda c: cat_count[c])
