"""Tests for sift.pipeline.prioritizer: score_cluster, prioritize, prioritize_all."""

import uuid

import pytest

from sift.config import PriorityThresholds, ScoringConfig, SeverityWeights
from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority, TechniqueRef


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_alert(severity: AlertSeverity) -> Alert:
    return Alert(id=str(uuid.uuid4()), title="t", severity=severity)


def make_cluster(
    alerts: list[Alert],
    iocs: list[str] | None = None,
    techniques: list[TechniqueRef] | None = None,
    confidence: float = 1.0,
) -> Cluster:
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=alerts,
        priority=ClusterPriority.MEDIUM,
        score=0.0,
        confidence=confidence,
        iocs=iocs or [],
        techniques=techniques or [],
    )


def make_technique(tech_id: str = "T1566") -> TechniqueRef:
    return TechniqueRef(
        technique_id=tech_id,
        technique_name="Phishing",
        tactic="Initial Access",
    )


# ---------------------------------------------------------------------------
# Lazy import so test collection does not fail before the module is written
# ---------------------------------------------------------------------------

from sift.pipeline.prioritizer import prioritize, prioritize_all, score_cluster


# ---------------------------------------------------------------------------
# score_cluster — base scoring
# ---------------------------------------------------------------------------

class TestScoreClusterBase:
    def test_single_medium_alert_default_confidence(self):
        """1 MEDIUM alert: base=5, multiplier=1.0 → score=5.0"""
        cluster = make_cluster([make_alert(AlertSeverity.MEDIUM)])
        result = score_cluster(cluster, SeverityWeights())
        assert result == 5.0

    def test_single_critical_alert(self):
        """1 CRITICAL alert: base=20, × 1.5 CRITICAL multiplier = 30.0"""
        cluster = make_cluster([make_alert(AlertSeverity.CRITICAL)])
        result = score_cluster(cluster, SeverityWeights())
        assert result == 30.0

    def test_three_high_alerts(self):
        """3 HIGH alerts: base=30, × 1.3 HIGH-count multiplier = 39.0"""
        alerts = [make_alert(AlertSeverity.HIGH) for _ in range(3)]
        cluster = make_cluster(alerts)
        result = score_cluster(cluster, SeverityWeights())
        assert result == 39.0


# ---------------------------------------------------------------------------
# score_cluster — multipliers
# ---------------------------------------------------------------------------

class TestScoreClusterMultipliers:
    def test_five_iocs_applies_1_2_multiplier(self):
        """5 unique IOCs triggers the × 1.2 IOC breadth multiplier."""
        iocs = ["ioc1", "ioc2", "ioc3", "ioc4", "ioc5"]
        cluster = make_cluster([make_alert(AlertSeverity.MEDIUM)], iocs=iocs)
        result = score_cluster(cluster, SeverityWeights())
        # base=5, × 1.2 = 6.0
        assert result == pytest.approx(6.0, rel=1e-9)

    def test_three_techniques_applies_1_1_multiplier(self):
        """3 ATT&CK techniques triggers the × 1.1 technique multiplier."""
        techniques = [make_technique(f"T{1000 + i}") for i in range(3)]
        cluster = make_cluster([make_alert(AlertSeverity.MEDIUM)], techniques=techniques)
        result = score_cluster(cluster, SeverityWeights())
        # base=5, × 1.1 = 5.5
        assert result == pytest.approx(5.5, rel=1e-9)

    def test_confidence_halves_score(self):
        """confidence=0.5 halves the final score."""
        cluster = make_cluster([make_alert(AlertSeverity.MEDIUM)], confidence=0.5)
        result = score_cluster(cluster, SeverityWeights())
        # base=5, × 0.5 = 2.5
        assert result == pytest.approx(2.5, rel=1e-9)


# ---------------------------------------------------------------------------
# prioritize — threshold mapping
# ---------------------------------------------------------------------------

class TestPrioritizeThresholds:
    """Default thresholds: low=5, medium=20, high=50, critical=100."""

    def _cluster_with_score(self, raw_score: float) -> Cluster:
        """Build a cluster whose score_cluster output equals raw_score (approx).

        Uses a single MEDIUM alert (weight=5) scaled by confidence to hit
        the target score precisely, bypassing multipliers.
        """
        confidence = raw_score / 5.0
        cluster = make_cluster([make_alert(AlertSeverity.MEDIUM)], confidence=confidence)
        return cluster

    def test_score_below_low_threshold_is_noise(self):
        """score < 5 → NOISE"""
        cluster = self._cluster_with_score(4.0)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.NOISE

    def test_score_at_low_threshold_is_low(self):
        """score == 5 → LOW (low boundary is inclusive for LOW tier)"""
        cluster = self._cluster_with_score(5.0)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.LOW

    def test_score_in_medium_range_is_medium(self):
        """score 20-49 → MEDIUM"""
        cluster = self._cluster_with_score(30.0)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.MEDIUM

    def test_score_in_high_range_is_high(self):
        """score 50-99 → HIGH"""
        cluster = self._cluster_with_score(60.0)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.HIGH

    def test_score_at_critical_threshold_is_critical(self):
        """score >= 100 → CRITICAL"""
        cluster = self._cluster_with_score(100.0)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.CRITICAL

    def test_score_just_below_medium_is_low(self):
        """score just below 20 → LOW"""
        cluster = self._cluster_with_score(19.0)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.LOW

    def test_score_just_below_high_is_medium(self):
        """score just below 50 → MEDIUM"""
        cluster = self._cluster_with_score(49.0)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.MEDIUM

    def test_score_just_below_critical_is_high(self):
        """score just below 100 → HIGH"""
        cluster = self._cluster_with_score(99.0)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.HIGH


# ---------------------------------------------------------------------------
# prioritize — immutability (model_copy pattern)
# ---------------------------------------------------------------------------

class TestPrioritizeImmutability:
    def test_prioritize_returns_new_cluster(self):
        """prioritize must return a new Cluster instance, not mutate the original."""
        cluster = make_cluster([make_alert(AlertSeverity.MEDIUM)])
        original_score = cluster.score
        result = prioritize(cluster)
        assert result is not cluster
        assert cluster.score == original_score  # original unchanged

    def test_result_has_updated_score_and_priority(self):
        """The returned cluster carries the newly computed score and priority."""
        cluster = make_cluster([make_alert(AlertSeverity.MEDIUM)])
        result = prioritize(cluster)
        assert result.score == 5.0
        assert result.priority == ClusterPriority.LOW


# ---------------------------------------------------------------------------
# prioritize_all
# ---------------------------------------------------------------------------

class TestPrioritizeAll:
    def test_sorts_by_score_descending(self):
        """prioritize_all must return clusters sorted by score high → low."""
        low = make_cluster([make_alert(AlertSeverity.LOW)])        # base=2
        medium = make_cluster([make_alert(AlertSeverity.MEDIUM)])  # base=5
        high = make_cluster([make_alert(AlertSeverity.HIGH)])      # base=10
        result = prioritize_all([low, high, medium])
        scores = [c.score for c in result]
        assert scores == sorted(scores, reverse=True)
        assert scores[0] >= scores[1] >= scores[2]

    def test_empty_list_returns_empty(self):
        """prioritize_all with an empty list must return []."""
        assert prioritize_all([]) == []


# ---------------------------------------------------------------------------
# Custom thresholds
# ---------------------------------------------------------------------------

class TestCustomThresholds:
    def test_custom_critical_threshold_at_50(self):
        """Overriding critical=50 promotes a score of 50 to CRITICAL."""
        custom_config = ScoringConfig(
            thresholds=PriorityThresholds(low=5, medium=20, high=30, critical=50)
        )
        # 5 HIGH alerts: base=50, no multipliers (< 3 HIGH count triggers × 1.3; we need exactly 50)
        # Use a MEDIUM alert with confidence=10.0 to get base=50 without multipliers.
        cluster = make_cluster([make_alert(AlertSeverity.MEDIUM)], confidence=10.0)
        result = prioritize(cluster, config=custom_config)
        assert result.score == pytest.approx(50.0, rel=1e-9)
        assert result.priority == ClusterPriority.CRITICAL
