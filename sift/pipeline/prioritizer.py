"""Cluster prioritizer for sift alert triage.

Calculates scores and assigns priority levels to alert clusters based on
severity weights, IOC volume, ATT&CK technique coverage, and confidence.
"""

from __future__ import annotations

from sift.config import ScoringConfig, SeverityWeights
from sift.models import Cluster, ClusterPriority


def score_cluster(cluster: Cluster, weights: SeverityWeights) -> float:
    """Calculate a numeric score for a cluster based on alert severities and multipliers.

    The base score is the sum of per-alert severity weights. Multipliers are
    then applied for the presence of high-severity alerts, IOC breadth, ATT&CK
    technique coverage, and the cluster's own confidence value.

    Args:
        cluster: The cluster to score.
        weights: Severity weight mapping from the active ScoringConfig.

    Returns:
        The final score, rounded to two decimal places.
    """
    # Base score: sum of severity weights across every alert in the cluster.
    base: float = sum(
        getattr(weights, alert.severity.value) for alert in cluster.alerts
    )

    multiplier: float = 1.0

    # × 1.5 if any alert is CRITICAL severity.
    if any(alert.severity.value == "CRITICAL" for alert in cluster.alerts):
        multiplier *= 1.5

    # × 1.3 if three or more alerts are HIGH severity.
    high_count = sum(1 for alert in cluster.alerts if alert.severity.value == "HIGH")
    if high_count >= 3:
        multiplier *= 1.3

    # × 1.2 if the cluster exposes five or more unique IOCs.
    if len(set(cluster.iocs)) >= 5:
        multiplier *= 1.2

    # × 1.1 if three or more distinct ATT&CK techniques are referenced.
    if len(cluster.techniques) >= 3:
        multiplier *= 1.1

    # Apply the cluster's own confidence as a final multiplier.
    multiplier *= cluster.confidence

    return round(base * multiplier, 2)


def _priority_from_score(score: float, config: ScoringConfig) -> ClusterPriority:
    """Map a numeric score to a ClusterPriority tier using threshold configuration.

    Args:
        score: The computed cluster score.
        config: ScoringConfig supplying the threshold boundaries.

    Returns:
        The appropriate ClusterPriority value.
    """
    t = config.thresholds
    if score < t.low:
        return ClusterPriority.NOISE
    if score < t.medium:
        return ClusterPriority.LOW
    if score < t.high:
        return ClusterPriority.MEDIUM
    if score < t.critical:
        return ClusterPriority.HIGH
    return ClusterPriority.CRITICAL


def prioritize(
    cluster: Cluster,
    config: ScoringConfig | None = None,
) -> Cluster:
    """Score and prioritize a single cluster.

    Computes the cluster score via :func:`score_cluster`, derives the
    :class:`~sift.models.ClusterPriority` from the active thresholds, and
    returns a new :class:`~sift.models.Cluster` instance (via ``model_copy``)
    with ``score`` and ``priority`` updated.

    Args:
        cluster: The cluster to evaluate.
        config: Scoring configuration to use. Defaults to
            ``ScoringConfig()`` (library defaults) when *None*.

    Returns:
        A new Cluster with updated ``score`` and ``priority`` fields.
    """
    if config is None:
        config = ScoringConfig()

    computed_score = score_cluster(cluster, config.weights)
    computed_priority = _priority_from_score(computed_score, config)

    return cluster.model_copy(
        update={"score": computed_score, "priority": computed_priority}
    )


def prioritize_all(
    clusters: list[Cluster],
    config: ScoringConfig | None = None,
) -> list[Cluster]:
    """Score and prioritize every cluster in a collection.

    Applies :func:`prioritize` to each cluster and returns the resulting list
    sorted by score in descending order so the most critical clusters appear
    first.

    Args:
        clusters: The clusters to evaluate.
        config: Scoring configuration shared across all clusters. Defaults to
            ``ScoringConfig()`` when *None*.

    Returns:
        A new list of prioritized Cluster objects, sorted by score descending.
    """
    if config is None:
        config = ScoringConfig()

    prioritized = [prioritize(c, config) for c in clusters]
    return sorted(prioritized, key=lambda c: c.score, reverse=True)
