"""Integration tests for the full sift pipeline against real fixture files.

Exercises the complete normalize → dedup → ioc_extract → cluster → prioritize
pipeline for every fixture scenario, then verifies that a TriageReport can be
constructed from the resulting data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sift.models import ClusterPriority, TriageReport
from sift.normalizers.generic import GenericNormalizer
from sift.pipeline.clusterer import cluster_alerts
from sift.pipeline.dedup import deduplicate
from sift.pipeline.ioc_extractor import enrich_alerts_iocs
from sift.pipeline.prioritizer import prioritize_all

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_and_normalize(filename: str):
    """Read a fixture file and return normalized Alert list."""
    path = FIXTURES / filename
    raw = path.read_text(encoding="utf-8")
    return GenericNormalizer().normalize(raw)


def _run_pipeline(filename: str):
    """Run the full pipeline on a fixture and return prioritized clusters."""
    alerts = _load_and_normalize(filename)
    deduped, _stats = deduplicate(alerts)
    enriched = enrich_alerts_iocs(deduped)
    clusters = cluster_alerts(enriched)
    return prioritize_all(clusters)


# ---------------------------------------------------------------------------
# phishing_campaign.json — 10 alerts, active phishing campaign
# ---------------------------------------------------------------------------

class TestPhishingCampaignPipeline:
    """10 alerts representing a multi-recipient phishing campaign."""

    FIXTURE = "phishing_campaign.json"

    def test_normalizes_to_ten_alerts(self):
        """The fixture contains exactly 10 alert records."""
        alerts = _load_and_normalize(self.FIXTURE)
        assert len(alerts) == 10

    def test_dedup_retains_at_least_eight_alerts(self):
        """Each alert is unique (different user/host/time); ≥8 survive dedup."""
        alerts = _load_and_normalize(self.FIXTURE)
        deduped, stats = deduplicate(alerts)
        assert len(deduped) >= 8

    def test_pipeline_produces_at_least_one_critical_cluster(self):
        """The phishing campaign with CRITICAL credential-submission alerts
        must produce at least one CRITICAL priority cluster."""
        clusters = _run_pipeline(self.FIXTURE)
        priorities = {c.priority for c in clusters}
        assert ClusterPriority.CRITICAL in priorities

    def test_at_least_one_cluster_has_iocs(self):
        """IOC extraction should populate at least one cluster's iocs list."""
        clusters = _run_pipeline(self.FIXTURE)
        assert any(len(c.iocs) > 0 for c in clusters)

    def test_top_cluster_score_exceeds_100(self):
        """The highest-scored cluster must clear the CRITICAL threshold (>100)."""
        clusters = _run_pipeline(self.FIXTURE)
        assert clusters[0].score > 100


# ---------------------------------------------------------------------------
# lateral_movement.json — 8 alerts, Mimikatz + lateral movement chain
# ---------------------------------------------------------------------------

class TestLateralMovementPipeline:
    """8 alerts representing a full Mimikatz-to-DC lateral movement chain."""

    FIXTURE = "lateral_movement.json"

    def test_normalizes_to_eight_alerts(self):
        """The fixture contains exactly 8 alert records."""
        alerts = _load_and_normalize(self.FIXTURE)
        assert len(alerts) == 8

    def test_all_alerts_are_high_or_critical_severity(self):
        """Every alert in this fixture is HIGH or CRITICAL — no noise."""
        alerts = _load_and_normalize(self.FIXTURE)
        high_or_critical = {ClusterPriority.HIGH.value, ClusterPriority.CRITICAL.value}
        for alert in alerts:
            assert alert.severity.value in high_or_critical, (
                f"Alert '{alert.id}' has unexpected severity '{alert.severity}'"
            )

    def test_pipeline_produces_at_least_one_critical_cluster(self):
        """Mimikatz + domain controller compromise should yield CRITICAL priority."""
        clusters = _run_pipeline(self.FIXTURE)
        priorities = {c.priority for c in clusters}
        assert ClusterPriority.CRITICAL in priorities

    def test_cluster_iocs_list_is_non_empty(self):
        """Shared source IP (10.10.5.42) across multiple alerts should be
        captured as a cluster IOC after enrichment."""
        clusters = _run_pipeline(self.FIXTURE)
        # At least one cluster must have a non-empty iocs list
        assert any(len(c.iocs) > 0 for c in clusters)


# ---------------------------------------------------------------------------
# fp_cluster.json — 12 alerts, false-positive / low-noise cluster
# ---------------------------------------------------------------------------

class TestFPClusterPipeline:
    """12 alerts that are all INFO/LOW-severity noise events (scanners, lockouts,
    PUA quarantines). The pipeline must identify these as NOISE or LOW priority.
    """

    FIXTURE = "fp_cluster.json"

    def test_normalizes_to_twelve_alerts(self):
        """The fixture contains exactly 12 alert records."""
        alerts = _load_and_normalize(self.FIXTURE)
        assert len(alerts) == 12

    def test_highest_priority_is_low_or_noise(self):
        """All alerts are INFO/LOW severity; the pipeline must not produce a
        HIGH or CRITICAL cluster from benign noise events."""
        clusters = _run_pipeline(self.FIXTURE)
        assert len(clusters) > 0, "Expected at least one cluster"
        top_priority = clusters[0].priority
        assert top_priority in (ClusterPriority.NOISE, ClusterPriority.LOW), (
            f"Expected NOISE or LOW as top priority, got {top_priority}"
        )

    def test_no_high_or_critical_clusters_present(self):
        """There must be zero HIGH or CRITICAL clusters in this all-noise set."""
        clusters = _run_pipeline(self.FIXTURE)
        for cluster in clusters:
            assert cluster.priority not in (ClusterPriority.HIGH, ClusterPriority.CRITICAL), (
                f"Unexpected {cluster.priority} cluster: '{cluster.label}'"
            )

    def test_exit_code_would_be_zero(self):
        """All NOISE/LOW clusters → overall exit code 0 (no escalation needed)."""
        clusters = _run_pipeline(self.FIXTURE)
        # exit_code == 1 for HIGH or CRITICAL; the combined code is 1 if any cluster has it
        combined_exit_code = 1 if any(c.priority.exit_code == 1 for c in clusters) else 0
        assert combined_exit_code == 0


# ---------------------------------------------------------------------------
# mixed.json — 15 alerts, C2 beaconing + ransomware + background noise
# ---------------------------------------------------------------------------

class TestMixedPipeline:
    """15 alerts mixing CRITICAL ransomware, HIGH C2 beaconing, and
    routine INFO/LOW noise events from the same time window."""

    FIXTURE = "mixed.json"

    def test_normalizes_to_fifteen_alerts(self):
        """The fixture contains exactly 15 alert records."""
        alerts = _load_and_normalize(self.FIXTURE)
        assert len(alerts) == 15

    def test_pipeline_produces_high_or_critical_cluster(self):
        """Ransomware and C2 beaconing events must surface a HIGH or CRITICAL cluster."""
        clusters = _run_pipeline(self.FIXTURE)
        priorities = {c.priority for c in clusters}
        assert ClusterPriority.HIGH in priorities or ClusterPriority.CRITICAL in priorities

    def test_pipeline_also_produces_noise_clusters(self):
        """Background INFO/LOW events should form distinct NOISE clusters below
        the high-severity signal clusters."""
        clusters = _run_pipeline(self.FIXTURE)
        priorities = {c.priority for c in clusters}
        assert ClusterPriority.NOISE in priorities or ClusterPriority.LOW in priorities, (
            "Expected at least some NOISE or LOW clusters alongside the high-severity ones"
        )

    def test_overall_exit_code_is_one(self):
        """At least one HIGH/CRITICAL cluster → combined exit code must be 1."""
        clusters = _run_pipeline(self.FIXTURE)
        combined_exit_code = 1 if any(c.priority.exit_code == 1 for c in clusters) else 0
        assert combined_exit_code == 1


# ---------------------------------------------------------------------------
# Full TriageReport construction from mixed.json
# ---------------------------------------------------------------------------

class TestTriageReportConstruction:
    """Verify that a complete TriageReport can be built from the mixed.json
    pipeline output and that all key properties are correctly computed."""

    FIXTURE = "mixed.json"

    @pytest.fixture(scope="class")
    def report(self) -> TriageReport:
        """Build a TriageReport from the full mixed.json pipeline."""
        raw = (FIXTURES / self.FIXTURE).read_text(encoding="utf-8")
        alerts = GenericNormalizer().normalize(raw)
        deduped, _stats = deduplicate(alerts)
        enriched = enrich_alerts_iocs(deduped)
        clusters = cluster_alerts(enriched)
        prioritized = prioritize_all(clusters)

        return TriageReport(
            input_file=self.FIXTURE,
            alerts_ingested=len(alerts),
            alerts_after_dedup=len(deduped),
            clusters=prioritized,
            summary=None,
            enrichment=None,
            manifest=None,
            analyzed_at=datetime.now(tz=timezone.utc),
        )

    def test_alerts_ingested_equals_fifteen(self, report: TriageReport):
        """alerts_ingested must reflect the raw fixture count (15)."""
        assert report.alerts_ingested == 15

    def test_clusters_is_non_empty(self, report: TriageReport):
        """The report must contain at least one cluster."""
        assert len(report.clusters) > 0

    def test_exit_code_is_one(self, report: TriageReport):
        """Mixed fixture contains ransomware/C2 → exit_code must be 1."""
        assert report.exit_code == 1

    def test_has_critical_is_bool(self, report: TriageReport):
        """has_critical is a computed property that must return a bool."""
        result = report.has_critical
        assert isinstance(result, bool)
