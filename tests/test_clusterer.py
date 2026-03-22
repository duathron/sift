"""Focused pytest tests for sift.pipeline.clusterer.cluster_alerts.

Covers all four clustering passes:
  Pass 1 — IOC overlap (Union-Find merge)
  Pass 2 — Same category + time window
  Pass 3 — Same (source_ip, dest_ip) pair + time window
  Pass 4 — Singletons

Also covers Cluster properties and sort order.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sift.config import ClusteringConfig
from sift.models import Alert, AlertSeverity, ClusterPriority
from sift.pipeline.clusterer import cluster_alerts

# ---------------------------------------------------------------------------
# Alert factory
# ---------------------------------------------------------------------------

def make_alert(
    id: str,
    title: str = "Alert",
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    iocs: list[str] | None = None,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    category: str | None = None,
    timestamp: datetime | None = None,
) -> Alert:
    return Alert(
        id=id,
        title=title,
        severity=severity,
        iocs=iocs or [],
        source_ip=source_ip,
        dest_ip=dest_ip,
        category=category,
        timestamp=timestamp,
    )


# Convenience timestamp anchors
_T0 = datetime(2026, 3, 22, 10, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Basic clustering
# ---------------------------------------------------------------------------

class TestBasicClustering:
    def test_empty_input_returns_empty_list(self):
        """Empty alert list → empty cluster list."""
        result = cluster_alerts([])
        assert result == []

    def test_single_alert_yields_one_cluster(self):
        """Single alert → exactly one cluster containing that alert."""
        a = make_alert("a1", title="Lone Wolf", timestamp=_T0)
        clusters = cluster_alerts([a])
        assert len(clusters) == 1
        assert len(clusters[0].alerts) == 1
        assert clusters[0].alerts[0].id == "a1"

    def test_two_disjoint_alerts_yield_two_singletons(self):
        """Two alerts with no IOC overlap and no common category → 2 singleton clusters."""
        a1 = make_alert("a1", title="Alert A", category="Malware", timestamp=_T0)
        a2 = make_alert("a2", title="Alert B", category="Network Scan", timestamp=_T0)
        clusters = cluster_alerts([a1, a2])
        assert len(clusters) == 2
        assert all(len(c.alerts) == 1 for c in clusters)


# ---------------------------------------------------------------------------
# Pass 1 — IOC overlap
# ---------------------------------------------------------------------------

class TestIOCOverlap:
    def test_two_alerts_sharing_one_ioc_merge(self):
        """Two alerts with a shared IOC are grouped into one cluster."""
        ioc = "185.220.101.47"
        a1 = make_alert("a1", iocs=[ioc], timestamp=_T0)
        a2 = make_alert("a2", iocs=[ioc], timestamp=_T0)
        clusters = cluster_alerts([a1, a2])
        assert len(clusters) == 1
        assert len(clusters[0].alerts) == 2

    def test_transitive_ioc_merge(self):
        """A-B share IOC-1, B-C share IOC-2 → all three merged (transitive union-find)."""
        a = make_alert("a1", iocs=["ioc-alpha"], timestamp=_T0)
        b = make_alert("a2", iocs=["ioc-alpha", "ioc-beta"], timestamp=_T0)
        c = make_alert("a3", iocs=["ioc-beta"], timestamp=_T0)
        clusters = cluster_alerts([a, b, c])
        assert len(clusters) == 1
        assert len(clusters[0].alerts) == 3

    def test_ioc_cluster_reason_mentions_ioc(self):
        """cluster_reason for an IOC-grouped cluster must reference the shared IOC or 'IOC'."""
        shared = "evil.example.com"
        a1 = make_alert("a1", iocs=[shared], timestamp=_T0)
        a2 = make_alert("a2", iocs=[shared], timestamp=_T0)
        clusters = cluster_alerts([a1, a2])
        assert len(clusters) == 1
        reason = clusters[0].cluster_reason
        assert "IOC" in reason or shared in reason


# ---------------------------------------------------------------------------
# Pass 2 — Same category + time window
# ---------------------------------------------------------------------------

class TestCategoryTimeWindow:
    def test_same_category_within_window_grouped(self):
        """Two alerts with the same category 10 min apart group under a 30-min window."""
        cfg = ClusteringConfig(time_window_minutes=30)
        a1 = make_alert("a1", category="Phishing", timestamp=_T0)
        a2 = make_alert("a2", category="Phishing", timestamp=_T0 + timedelta(minutes=10))
        clusters = cluster_alerts([a1, a2], cfg)
        sizes = [len(c.alerts) for c in clusters]
        assert 2 in sizes

    def test_same_category_outside_window_not_grouped(self):
        """Two alerts with the same category 60 min apart do NOT group under a 30-min window."""
        cfg = ClusteringConfig(time_window_minutes=30)
        a1 = make_alert("a1", category="Phishing", timestamp=_T0)
        a2 = make_alert("a2", category="Phishing", timestamp=_T0 + timedelta(minutes=60))
        clusters = cluster_alerts([a1, a2], cfg)
        assert all(len(c.alerts) == 1 for c in clusters)

    def test_different_category_same_time_not_grouped_by_category(self):
        """Alerts with different categories at the same time are NOT merged by Pass 2."""
        cfg = ClusteringConfig(time_window_minutes=30)
        a1 = make_alert("a1", category="Malware", timestamp=_T0)
        a2 = make_alert("a2", category="Network Scan", timestamp=_T0)
        clusters = cluster_alerts([a1, a2], cfg)
        assert all(len(c.alerts) == 1 for c in clusters)


# ---------------------------------------------------------------------------
# Pass 3 — IP-pair + time window
# ---------------------------------------------------------------------------

class TestIPPairTimeWindow:
    def test_same_ip_pair_within_window_grouped(self):
        """Two alerts with identical (source_ip, dest_ip) within time window are grouped."""
        cfg = ClusteringConfig(time_window_minutes=30)
        a1 = make_alert("a1", source_ip="10.0.0.5", dest_ip="198.51.100.1", timestamp=_T0)
        a2 = make_alert("a2", source_ip="10.0.0.5", dest_ip="198.51.100.1",
                         timestamp=_T0 + timedelta(minutes=5))
        clusters = cluster_alerts([a1, a2], cfg)
        sizes = [len(c.alerts) for c in clusters]
        assert 2 in sizes

    def test_same_source_different_dest_not_grouped(self):
        """Same source_ip but different dest_ip → NOT merged by IP-pair pass."""
        cfg = ClusteringConfig(time_window_minutes=30)
        a1 = make_alert("a1", source_ip="10.0.0.5", dest_ip="198.51.100.1", timestamp=_T0)
        a2 = make_alert("a2", source_ip="10.0.0.5", dest_ip="198.51.100.2", timestamp=_T0)
        clusters = cluster_alerts([a1, a2], cfg)
        assert all(len(c.alerts) == 1 for c in clusters)


# ---------------------------------------------------------------------------
# Cluster properties
# ---------------------------------------------------------------------------

class TestClusterProperties:
    def test_cluster_iocs_are_union_of_member_iocs(self):
        """Cluster.iocs must contain all unique IOCs from all member alerts."""
        a1 = make_alert("a1", iocs=["1.1.1.1", "evil.com"])
        a2 = make_alert("a2", iocs=["evil.com", "2.2.2.2"])
        clusters = cluster_alerts([a1, a2])
        big = max(clusters, key=lambda c: len(c.alerts))
        assert "1.1.1.1" in big.iocs
        assert "evil.com" in big.iocs
        assert "2.2.2.2" in big.iocs

    def test_cluster_first_seen_is_min_timestamp(self):
        """Cluster.first_seen equals the earliest timestamp across member alerts."""
        t_early = _T0
        t_late = _T0 + timedelta(hours=2)
        a1 = make_alert("a1", iocs=["x"], timestamp=t_late)
        a2 = make_alert("a2", iocs=["x"], timestamp=t_early)
        clusters = cluster_alerts([a1, a2])
        assert len(clusters) == 1
        assert clusters[0].first_seen == t_early

    def test_cluster_last_seen_is_max_timestamp(self):
        """Cluster.last_seen equals the latest timestamp across member alerts."""
        t_early = _T0
        t_late = _T0 + timedelta(hours=3)
        a1 = make_alert("a1", iocs=["x"], timestamp=t_early)
        a2 = make_alert("a2", iocs=["x"], timestamp=t_late)
        clusters = cluster_alerts([a1, a2])
        assert len(clusters) == 1
        assert clusters[0].last_seen == t_late

    def test_cluster_alerts_contains_all_member_objects(self):
        """Cluster.alerts must contain the exact Alert objects that were grouped."""
        shared_ioc = "malware.hash.md5"
        a1 = make_alert("a1", iocs=[shared_ioc])
        a2 = make_alert("a2", iocs=[shared_ioc])
        clusters = cluster_alerts([a1, a2])
        assert len(clusters) == 1
        member_ids = {a.id for a in clusters[0].alerts}
        assert "a1" in member_ids
        assert "a2" in member_ids

    def test_cluster_priority_is_medium(self):
        """clusterer.py leaves priority as MEDIUM; prioritizer.py assigns real values."""
        a1 = make_alert("a1", iocs=["shared"], severity=AlertSeverity.CRITICAL)
        a2 = make_alert("a2", iocs=["shared"], severity=AlertSeverity.CRITICAL)
        clusters = cluster_alerts([a1, a2])
        for cluster in clusters:
            assert cluster.priority == ClusterPriority.MEDIUM

    def test_singleton_priority_is_medium(self):
        """Singleton clusters also carry ClusterPriority.MEDIUM from the clusterer."""
        a = make_alert("a1", severity=AlertSeverity.HIGH, timestamp=_T0)
        clusters = cluster_alerts([a])
        assert clusters[0].priority == ClusterPriority.MEDIUM


# ---------------------------------------------------------------------------
# Sort order
# ---------------------------------------------------------------------------

class TestSortOrder:
    def test_clusters_sorted_by_score_descending(self):
        """Higher-severity clusters must appear before lower-severity ones in the result."""
        # Low-score cluster: one INFO alert (score = 1)
        low_a = make_alert("low1", severity=AlertSeverity.INFO, timestamp=_T0)

        # High-score cluster: two CRITICAL alerts sharing an IOC (score = 40)
        shared_ioc = "campaign.c2.bad"
        hi_a = make_alert("hi1", severity=AlertSeverity.CRITICAL,
                           iocs=[shared_ioc], timestamp=_T0)
        hi_b = make_alert("hi2", severity=AlertSeverity.CRITICAL,
                           iocs=[shared_ioc], timestamp=_T0 + timedelta(minutes=1))

        clusters = cluster_alerts([low_a, hi_a, hi_b])
        assert len(clusters) == 2
        assert clusters[0].score >= clusters[1].score

    def test_scores_are_non_increasing(self):
        """For any result list, each cluster's score is >= the next one's score."""
        a1 = make_alert("a1", severity=AlertSeverity.LOW, timestamp=_T0)
        a2 = make_alert("a2", severity=AlertSeverity.HIGH,
                         iocs=["link"], timestamp=_T0)
        a3 = make_alert("a3", severity=AlertSeverity.HIGH,
                         iocs=["link"], timestamp=_T0 + timedelta(minutes=1))
        a4 = make_alert("a4", severity=AlertSeverity.MEDIUM, timestamp=_T0)
        clusters = cluster_alerts([a1, a2, a3, a4])
        scores = [c.score for c in clusters]
        assert scores == sorted(scores, reverse=True)
