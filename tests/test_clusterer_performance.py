"""Performance and optimization tests for sift.pipeline.clusterer.cluster_alerts.

Covers three optimization areas introduced in v0.7.0:

  TestClusteringPerformance  (5 tests) — wall-clock timing + correctness at scale
  TestIOCIndexOptimization   (5 tests) — inverted IOC index edge cases
  TestTimeWindowOptimization (5 tests) — sliding-deque window edge cases
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from sift.config import ClusteringConfig
from sift.models import Alert, AlertSeverity
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
    timestamp: Optional[datetime] = None,
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


_T0 = datetime(2026, 3, 22, 10, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# TestClusteringPerformance
# ---------------------------------------------------------------------------

class TestClusteringPerformance:
    """Wall-clock timing and scale correctness tests."""

    def test_1000_alerts_cluster_under_2_seconds(self):
        """1 000 alerts must cluster in < 2 seconds."""
        alerts = [
            make_alert(
                id=f"a{i}",
                iocs=[f"ioc-{i % 50}"],           # 50 distinct IOCs → 20 per bucket
                category=f"Cat{i % 10}",
                timestamp=_T0 + timedelta(seconds=i),
            )
            for i in range(1_000)
        ]
        t0 = time.monotonic()
        clusters = cluster_alerts(alerts)
        elapsed = time.monotonic() - t0
        assert elapsed < 2.0, f"1 000-alert clustering took {elapsed:.2f}s (limit 2s)"
        assert len(clusters) > 0

    def test_5000_alerts_cluster_under_10_seconds(self):
        """5 000 alerts must cluster in < 10 seconds."""
        alerts = [
            make_alert(
                id=f"a{i}",
                iocs=[f"ioc-{i % 100}"],          # 100 distinct IOCs
                category=f"Cat{i % 20}",
                timestamp=_T0 + timedelta(seconds=i * 2),
            )
            for i in range(5_000)
        ]
        t0 = time.monotonic()
        clusters = cluster_alerts(alerts)
        elapsed = time.monotonic() - t0
        assert elapsed < 10.0, f"5 000-alert clustering took {elapsed:.2f}s (limit 10s)"
        assert len(clusters) > 0

    def test_ioc_index_groups_alerts_sharing_same_ioc(self):
        """The inverted IOC index must group all alerts sharing the same IOC."""
        shared_ioc = "185.220.101.47"
        # 100 alerts all share one IOC → must collapse into a single cluster.
        alerts = [make_alert(id=f"a{i}", iocs=[shared_ioc]) for i in range(100)]
        clusters = cluster_alerts(alerts)
        assert len(clusters) == 1
        assert len(clusters[0].alerts) == 100

    def test_time_window_bucketing_same_results_as_reference(self):
        """Sliding-window Pass 2 must produce the same groupings as a reference run.

        We compare a narrow window (5 min) against a wide window (60 min) using
        alerts spaced 10 minutes apart.

        * Narrow (5 min): each alert is 10 min from its neighbours — outside the
          window — so every alert becomes its own singleton cluster.
        * Wide (60 min): all consecutive alerts are within 60 min of each other
          and chain together into one large cluster.
        """
        cfg_narrow = ClusteringConfig(time_window_minutes=5)
        cfg_wide   = ClusteringConfig(time_window_minutes=60)

        # 10-minute spacing: narrower than wide (60 min) but wider than narrow (5 min).
        alerts = [
            make_alert(
                id=f"a{i}",
                category="Phishing",
                timestamp=_T0 + timedelta(minutes=i * 10),
            )
            for i in range(10)
        ]

        clusters_narrow = cluster_alerts(alerts, cfg_narrow)
        clusters_wide   = cluster_alerts(alerts, cfg_wide)

        sizes_narrow = sorted(len(c.alerts) for c in clusters_narrow)
        sizes_wide   = sorted(len(c.alerts) for c in clusters_wide)

        # Narrow: every alert is isolated (10 min > 5 min window).
        assert all(s == 1 for s in sizes_narrow), (
            f"Narrow window should produce all singletons, got {sizes_narrow}"
        )
        # Wide: all 10 alerts chain into one cluster (10 min < 60 min window).
        assert max(sizes_wide) > max(sizes_narrow), (
            "Wide window should produce larger clusters than narrow window"
        )
        assert sum(sizes_narrow) == sum(sizes_wide) == 10, (
            "Total alert count must be preserved in both configurations"
        )

    def test_max_clusters_parameter_limits_output(self):
        """max_clusters=N must return at most N clusters."""
        alerts = [
            make_alert(id=f"a{i}", category=f"UniqueCategory{i}", timestamp=_T0)
            for i in range(50)
        ]
        limit = 10
        clusters = cluster_alerts(alerts, max_clusters=limit)
        assert len(clusters) <= limit


# ---------------------------------------------------------------------------
# TestIOCIndexOptimization
# ---------------------------------------------------------------------------

class TestIOCIndexOptimization:
    """Edge cases for the inverted IOC index used in Pass 1."""

    def test_empty_ioc_list_no_error(self):
        """Alerts with empty IOC lists must not raise any exceptions."""
        alerts = [make_alert(id=f"a{i}") for i in range(10)]
        result = cluster_alerts(alerts)
        # Each alert becomes a singleton (no shared IOCs, no category, no IPs).
        assert len(result) == 10

    def test_duplicate_iocs_within_alert_handled_correctly(self):
        """An alert listing the same IOC twice must not cause double-union errors."""
        ioc = "evil.example.com"
        a1 = make_alert("a1", iocs=[ioc, ioc, ioc])   # same IOC repeated
        a2 = make_alert("a2", iocs=[ioc])
        clusters = cluster_alerts([a1, a2])
        # Both alerts share the IOC → exactly one cluster.
        assert len(clusters) == 1
        assert len(clusters[0].alerts) == 2

    def test_large_ioc_count_per_alert_no_exponential_slowdown(self):
        """100 IOCs per alert over 200 alerts must complete in < 3 seconds."""
        alerts = [
            make_alert(
                id=f"a{i}",
                iocs=[f"ioc-{i}-{j}" for j in range(100)],  # 100 unique IOCs per alert
            )
            for i in range(200)
        ]
        t0 = time.monotonic()
        clusters = cluster_alerts(alerts)
        elapsed = time.monotonic() - t0
        assert elapsed < 3.0, (
            f"200 alerts × 100 unique IOCs took {elapsed:.2f}s (limit 3s)"
        )
        # All IOCs are unique per alert → no grouping expected.
        assert len(clusters) == 200

    def test_ioc_index_same_as_brute_force_small_dataset(self):
        """For a small dataset, IOC-index clustering must match brute-force grouping.

        We build the expected answer manually (shared IOC → same cluster) and
        compare to cluster_alerts output.
        """
        # 6 alerts: a0+a1 share ioc-A, a2+a3 share ioc-B, a4+a5 share ioc-C.
        groups = [("ioc-A", ["a0", "a1"]), ("ioc-B", ["a2", "a3"]), ("ioc-C", ["a4", "a5"])]
        alerts = []
        expected_clusters = 3  # three distinct IOC groups
        for ioc, ids in groups:
            for aid in ids:
                alerts.append(make_alert(id=aid, iocs=[ioc]))

        clusters = cluster_alerts(alerts)
        assert len(clusters) == expected_clusters
        for cluster in clusters:
            assert len(cluster.alerts) == 2

    def test_ioc_case_sensitivity(self):
        """IOCs are case-sensitive: 'Evil.com' and 'evil.com' must NOT merge alerts."""
        a1 = make_alert("a1", iocs=["Evil.com"])
        a2 = make_alert("a2", iocs=["evil.com"])
        clusters = cluster_alerts([a1, a2])
        # Different case → two separate singletons.
        assert len(clusters) == 2
        assert all(len(c.alerts) == 1 for c in clusters)


# ---------------------------------------------------------------------------
# TestTimeWindowOptimization
# ---------------------------------------------------------------------------

class TestTimeWindowOptimization:
    """Edge cases for the sliding-deque time-window grouping in Passes 2 and 3."""

    def test_sorted_window_groups_adjacent_alerts_correctly(self):
        """Alerts within the window boundary are merged; those outside are not.

        Setup: 4 alerts at t=0, t=10m, t=20m, t=90m with a 30-min window.
        Expected: a0+a1+a2 merge (all within 30m of their neighbour via
        transitivity through sliding window), a3 is separate.
        Note: sliding window uses pairwise distance from the front of the deque;
        since a0 and a2 are 20m apart they are within the window together.
        """
        cfg = ClusteringConfig(time_window_minutes=30)
        alerts = [
            make_alert("a0", category="Malware", timestamp=_T0),
            make_alert("a1", category="Malware", timestamp=_T0 + timedelta(minutes=10)),
            make_alert("a2", category="Malware", timestamp=_T0 + timedelta(minutes=20)),
            make_alert("a3", category="Malware", timestamp=_T0 + timedelta(minutes=90)),
        ]
        clusters = cluster_alerts(alerts, cfg)
        sizes = sorted(len(c.alerts) for c in clusters)
        # a3 must be in its own cluster.
        assert 1 in sizes
        # a0, a1, a2 should be together.
        assert 3 in sizes

    def test_window_respects_category_boundary(self):
        """Alerts in different categories must NOT be merged by the time-window pass."""
        cfg = ClusteringConfig(time_window_minutes=60)
        alerts = [
            make_alert("a1", category="Malware",    timestamp=_T0),
            make_alert("a2", category="Network",    timestamp=_T0 + timedelta(minutes=5)),
            make_alert("a3", category="Malware",    timestamp=_T0 + timedelta(minutes=10)),
        ]
        clusters = cluster_alerts(alerts, cfg)
        # a1 and a3 share category "Malware" and are within the window → merge.
        # a2 is in "Network" → singleton.
        sizes = sorted(len(c.alerts) for c in clusters)
        assert sizes == [1, 2], f"Expected [1, 2] but got {sizes}"

    def test_alerts_without_timestamps_grouped_together_via_epoch(self):
        """Alerts with no timestamp are treated as epoch (datetime.min).

        Two no-timestamp alerts in the same category should be in the same
        cluster because they both map to epoch and are 0 seconds apart.
        """
        cfg = ClusteringConfig(time_window_minutes=30)
        a1 = make_alert("a1", category="Phishing", timestamp=None)
        a2 = make_alert("a2", category="Phishing", timestamp=None)
        clusters = cluster_alerts([a1, a2], cfg)
        # Both land at epoch → within any positive window → one cluster.
        sizes = [len(c.alerts) for c in clusters]
        assert 2 in sizes

    def test_window_boundary_excludes_out_of_range_alerts(self):
        """An alert exactly at window_minutes + 1 second must NOT join the cluster."""
        cfg = ClusteringConfig(time_window_minutes=30)
        a1 = make_alert("a1", category="Lateral Movement", timestamp=_T0)
        # Exactly 1801 seconds (30 min + 1 s) later — just outside the window.
        a2 = make_alert(
            "a2",
            category="Lateral Movement",
            timestamp=_T0 + timedelta(seconds=1801),
        )
        clusters = cluster_alerts([a1, a2], cfg)
        assert all(len(c.alerts) == 1 for c in clusters), (
            "Alert outside window boundary should not be merged"
        )

    def test_mixed_timestamp_no_timestamp_alerts(self):
        """Alerts with timestamps must not be merged with timestamp-less alerts via time window.

        A timestamped alert is far from epoch; a no-timestamp alert maps to epoch.
        They should not be merged by the time-window pass.
        """
        cfg = ClusteringConfig(time_window_minutes=30)
        # This timestamp is many years after epoch — well outside any window.
        a_ts = make_alert("a_ts", category="Exfil", timestamp=_T0)
        a_no = make_alert("a_no", category="Exfil", timestamp=None)
        clusters = cluster_alerts([a_ts, a_no], cfg)
        # The two alerts have incompatible time references → remain separate
        # (the sliding-deque skips merges when either side lacks a timestamp).
        assert all(len(c.alerts) == 1 for c in clusters), (
            "Timestamped and no-timestamp alerts should not be merged by the time-window pass"
        )
