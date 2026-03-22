"""Tests for sift pipeline stages: dedup, ioc_extractor, clusterer, prioritizer."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority
from sift.pipeline.dedup import DeduplicatorConfig, deduplicate
from sift.pipeline.ioc_extractor import detect_ioc_type, enrich_alert_iocs, extract_iocs
from sift.pipeline.clusterer import cluster_alerts
from sift.pipeline.prioritizer import prioritize, prioritize_all
from sift.config import ScoringConfig, ClusteringConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(
    title="Test Alert",
    severity=AlertSeverity.MEDIUM,
    source_ip=None,
    dest_ip=None,
    category=None,
    iocs=None,
    timestamp=None,
) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title=title,
        severity=severity,
        source_ip=source_ip,
        dest_ip=dest_ip,
        category=category,
        iocs=iocs or [],
        timestamp=timestamp or datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------

class TestDedup:
    def test_no_duplicates(self):
        alerts = [make_alert("Alert A"), make_alert("Alert B")]
        result, stats = deduplicate(alerts)
        assert stats.deduplicated_count == 2
        assert stats.removed_count == 0

    def test_identical_fingerprint_within_window(self):
        now = datetime.now(tz=timezone.utc)
        a1 = make_alert("Phishing Detected", source_ip="10.0.0.1", dest_ip="8.8.8.8", timestamp=now)
        a2 = make_alert("Phishing Detected", source_ip="10.0.0.1", dest_ip="8.8.8.8",
                        timestamp=now + timedelta(minutes=2))
        result, stats = deduplicate([a1, a2], DeduplicatorConfig(time_window_minutes=5))
        assert stats.deduplicated_count == 1
        assert stats.removed_count == 1

    def test_different_fingerprints_not_deduped(self):
        a1 = make_alert("Alert A", source_ip="10.0.0.1")
        a2 = make_alert("Alert B", source_ip="10.0.0.1")
        result, stats = deduplicate([a1, a2])
        assert stats.deduplicated_count == 2

    def test_outside_time_window_not_deduped(self):
        now = datetime.now(tz=timezone.utc)
        a1 = make_alert("Same Alert", source_ip="10.0.0.1", timestamp=now)
        a2 = make_alert("Same Alert", source_ip="10.0.0.1", timestamp=now + timedelta(minutes=10))
        result, stats = deduplicate([a1, a2], DeduplicatorConfig(time_window_minutes=5))
        assert stats.deduplicated_count == 2

    def test_empty_list(self):
        result, stats = deduplicate([])
        assert result == []
        assert stats.original_count == 0

    def test_single_alert(self):
        result, stats = deduplicate([make_alert()])
        assert stats.deduplicated_count == 1

    def test_removed_pct(self):
        now = datetime.now(tz=timezone.utc)
        alerts = [
            make_alert("X", source_ip="1.1.1.1", timestamp=now),
            make_alert("X", source_ip="1.1.1.1", timestamp=now + timedelta(minutes=1)),
            make_alert("Y", source_ip="2.2.2.2", timestamp=now),
        ]
        _, stats = deduplicate(alerts, DeduplicatorConfig(time_window_minutes=5))
        assert stats.removed_count == 1
        assert 30 < stats.removed_pct < 40


# ---------------------------------------------------------------------------
# IOC Extractor
# ---------------------------------------------------------------------------

class TestIOCExtractor:
    def test_extract_ipv4(self):
        iocs = extract_iocs("Connection to 185.220.101.47 detected")
        assert "185.220.101.47" in iocs

    def test_private_ip_excluded(self):
        iocs = extract_iocs("Source: 192.168.1.1 Dest: 10.0.0.5")
        assert "192.168.1.1" not in iocs
        assert "10.0.0.5" not in iocs

    def test_extract_domain(self):
        iocs = extract_iocs("DNS query to evil-phish.ru detected")
        assert "evil-phish.ru" in iocs

    def test_extract_url(self):
        iocs = extract_iocs("User clicked https://phishing.example.com/login")
        assert any("phishing.example.com" in i or "https://" in i for i in iocs)

    def test_extract_md5(self):
        iocs = extract_iocs("Hash: d41d8cd98f00b204e9800998ecf8427e")
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs

    def test_extract_sha256(self):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract_iocs(f"Malware hash: {sha}")
        assert sha in iocs

    def test_no_iocs(self):
        iocs = extract_iocs("No indicators here, just a normal log entry.")
        assert iocs == []

    def test_detect_ioc_type_ip(self):
        assert detect_ioc_type("185.220.101.47") == "ip"

    def test_detect_ioc_type_domain(self):
        assert detect_ioc_type("evil.phish.ru") == "domain"

    def test_detect_ioc_type_md5(self):
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash_md5"

    def test_detect_ioc_type_sha256(self):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_ioc_type(sha) == "hash_sha256"

    def test_enrich_alert_iocs(self):
        alert = make_alert(
            title="Connection to 185.220.101.47",
            dest_ip="185.220.101.47",
        )
        enriched = enrich_alert_iocs(alert)
        assert "185.220.101.47" in enriched.iocs

    def test_enrich_preserves_existing_iocs(self):
        alert = make_alert(iocs=["existing.ioc"])
        enriched = enrich_alert_iocs(alert)
        assert "existing.ioc" in enriched.iocs


# ---------------------------------------------------------------------------
# Clusterer
# ---------------------------------------------------------------------------

class TestClusterer:
    def test_single_alert_is_singleton(self):
        alerts = [make_alert("Lone Alert")]
        clusters = cluster_alerts(alerts)
        assert len(clusters) == 1
        assert len(clusters[0].alerts) == 1

    def test_shared_ioc_groups_alerts(self):
        ioc = "185.220.101.47"
        a1 = make_alert("Alert A", iocs=[ioc])
        a2 = make_alert("Alert B", iocs=[ioc])
        a3 = make_alert("Alert C", iocs=[])
        clusters = cluster_alerts([a1, a2, a3])
        # a1 and a2 share IOC → same cluster
        sizes = sorted([len(c.alerts) for c in clusters], reverse=True)
        assert sizes[0] == 2

    def test_cluster_iocs_aggregated(self):
        a1 = make_alert(iocs=["1.1.1.1", "evil.com"])
        a2 = make_alert(iocs=["evil.com", "2.2.2.2"])
        clusters = cluster_alerts([a1, a2])
        big_cluster = max(clusters, key=lambda c: len(c.alerts))
        assert "1.1.1.1" in big_cluster.iocs
        assert "evil.com" in big_cluster.iocs
        assert "2.2.2.2" in big_cluster.iocs

    def test_empty_alerts(self):
        clusters = cluster_alerts([])
        assert clusters == []

    def test_first_last_seen(self):
        now = datetime.now(tz=timezone.utc)
        a1 = make_alert(iocs=["x"], timestamp=now)
        a2 = make_alert(iocs=["x"], timestamp=now + timedelta(hours=1))
        clusters = cluster_alerts([a1, a2])
        c = clusters[0]
        assert c.first_seen == now
        assert c.last_seen == now + timedelta(hours=1)

    def test_config_respected(self):
        cfg = ClusteringConfig(max_cluster_size=1, time_window_minutes=0)
        alerts = [make_alert() for _ in range(3)]
        clusters = cluster_alerts(alerts, cfg)
        # No time-window grouping (0 minutes), no IOC overlap
        assert len(clusters) == 3


# ---------------------------------------------------------------------------
# Prioritizer
# ---------------------------------------------------------------------------

class TestPrioritizer:
    def _make_cluster(self, alerts, iocs=None) -> Cluster:
        import uuid as _uuid
        return Cluster(
            id=str(_uuid.uuid4()),
            label="Test Cluster",
            alerts=alerts,
            priority=ClusterPriority.MEDIUM,
            score=0.0,
            iocs=iocs or [],
            techniques=[],
        )

    def test_single_info_alert_is_noise(self):
        alerts = [make_alert(severity=AlertSeverity.INFO)]
        cluster = self._make_cluster(alerts)
        result = prioritize(cluster)
        assert result.priority in (ClusterPriority.NOISE, ClusterPriority.LOW)

    def test_critical_alert_cluster_is_critical(self):
        alerts = [make_alert(severity=AlertSeverity.CRITICAL) for _ in range(5)]
        cluster = self._make_cluster(alerts)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.CRITICAL

    def test_score_increases_with_count(self):
        low_cluster = self._make_cluster([make_alert(severity=AlertSeverity.HIGH)])
        high_cluster = self._make_cluster([make_alert(severity=AlertSeverity.HIGH)] * 5)
        low_result = prioritize(low_cluster)
        high_result = prioritize(high_cluster)
        assert high_result.score > low_result.score

    def test_prioritize_all_sorted(self):
        c1 = self._make_cluster([make_alert(severity=AlertSeverity.INFO)])
        c2 = self._make_cluster([make_alert(severity=AlertSeverity.CRITICAL)] * 3)
        results = prioritize_all([c1, c2])
        assert results[0].score >= results[1].score

    def test_empty_cluster_list(self):
        results = prioritize_all([])
        assert results == []
