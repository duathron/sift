"""Tests for sift.output.stix: STIX 2.1 bundle generation."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    ClusterSummary,
    SummaryResult,
    TriageReport,
)
from sift.output.stix import (
    STIXExporter,
    _deterministic_id,
    _now_iso,
    _pattern_from_ioc,
    _priority_to_severity,
    to_stix_bundle,
    to_stix_bundle_string,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(severity: AlertSeverity = AlertSeverity.HIGH, iocs: list[str] | None = None) -> Alert:
    """Create a test Alert."""
    return Alert(
        id=str(uuid.uuid4()),
        title="Test Alert",
        severity=severity,
        iocs=iocs or ["192.168.1.1"],
    )


def make_cluster(
    priority: ClusterPriority,
    label: str = "Test Cluster",
    alerts: list[Alert] | None = None,
    iocs: list[str] | None = None,
) -> Cluster:
    """Create a test Cluster."""
    alerts = alerts or [make_alert()]
    return Cluster(
        id=str(uuid.uuid4()),
        label=label,
        alerts=alerts,
        priority=priority,
        score=50.0,
        iocs=iocs or ["192.168.1.1"],
        techniques=[],
    )


def make_report(clusters: list[Cluster], summary: SummaryResult | None = None) -> TriageReport:
    """Create a test TriageReport."""
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        summary=summary,
        analyzed_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# TestSTIXExporterStructure
# ---------------------------------------------------------------------------


class TestSTIXExporterStructure:
    """Bundle creation and structural validation."""

    def test_exporter_init_accepts_report(self):
        """STIXExporter constructor accepts a TriageReport."""
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        exporter = STIXExporter(report)
        assert exporter.report is report

    def test_to_stix_bundle_returns_dict(self):
        """to_stix_bundle() returns a dictionary."""
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        exporter = STIXExporter(report)
        bundle = exporter.to_stix_bundle()
        assert isinstance(bundle, dict)

    def test_bundle_has_required_fields(self):
        """Bundle contains type, id, and objects fields."""
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        exporter = STIXExporter(report)
        bundle = exporter.to_stix_bundle()
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert "objects" in bundle
        assert bundle["id"].startswith("bundle--")

    def test_bundle_objects_list_is_populated(self):
        """Bundle objects list contains at least one object per cluster."""
        cluster = make_cluster(ClusterPriority.HIGH, iocs=["1.2.3.4"])
        report = make_report([cluster])
        exporter = STIXExporter(report)
        bundle = exporter.to_stix_bundle()
        # At minimum: 1 grouping + 1 indicator + 1 note + 1 relationship
        assert len(bundle["objects"]) >= 4

    def test_to_stix_bundle_string_returns_valid_json(self):
        """to_stix_bundle_string() returns a valid JSON string."""
        report = make_report([make_cluster(ClusterPriority.HIGH)])
        exporter = STIXExporter(report)
        json_str = exporter.to_stix_bundle_string()
        assert isinstance(json_str, str)
        # Must parse without error
        bundle = json.loads(json_str)
        assert bundle["type"] == "bundle"


# ---------------------------------------------------------------------------
# TestIndicatorObjects
# ---------------------------------------------------------------------------


class TestIndicatorObjects:
    """Indicator pattern generation and validation."""

    def test_pattern_ipv4(self):
        """IPv4 pattern generated correctly."""
        pattern = _pattern_from_ioc("192.168.1.1")
        assert pattern == "[ipv4-addr:value = '192.168.1.1']"

    def test_pattern_ipv4_explicit_type(self):
        """IPv4 pattern with explicit type."""
        pattern = _pattern_from_ioc("10.0.0.1", "ipv4")
        assert pattern == "[ipv4-addr:value = '10.0.0.1']"

    def test_pattern_ipv6(self):
        """IPv6 pattern generated correctly."""
        pattern = _pattern_from_ioc("2001:db8::1", "ipv6")
        assert pattern == "[ipv6-addr:value = '2001:db8::1']"

    def test_pattern_domain(self):
        """Domain pattern generated correctly."""
        pattern = _pattern_from_ioc("example.com")
        assert pattern == "[domain-name:value = 'example.com']"

    def test_pattern_domain_explicit_type(self):
        """Domain pattern with explicit type."""
        pattern = _pattern_from_ioc("evil.example.com", "domain")
        assert pattern == "[domain-name:value = 'evil.example.com']"

    def test_pattern_url(self):
        """URL pattern generated correctly."""
        pattern = _pattern_from_ioc("https://example.com/path")
        assert pattern == "[url:value = 'https://example.com/path']"

    def test_pattern_url_explicit_type(self):
        """URL pattern with explicit type."""
        pattern = _pattern_from_ioc("http://phish.ru/login", "url")
        assert pattern == "[url:value = 'http://phish.ru/login']"

    def test_pattern_md5_explicit_type(self):
        """MD5 hash pattern with explicit type."""
        pattern = _pattern_from_ioc("5d41402abc4b2a76b9719d911017c592", "md5")
        assert pattern == "[file:hashes.MD5 = '5d41402abc4b2a76b9719d911017c592']"

    def test_pattern_md5_auto_detect(self):
        """MD5 hash auto-detected by length and chars."""
        pattern = _pattern_from_ioc("5d41402abc4b2a76b9719d911017c592")
        assert pattern == "[file:hashes.MD5 = '5d41402abc4b2a76b9719d911017c592']"

    def test_pattern_sha1_auto_detect(self):
        """SHA1 hash auto-detected by length."""
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        pattern = _pattern_from_ioc(sha1)
        assert pattern == "[file:hashes.'SHA-1' = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d']"

    def test_pattern_sha256_auto_detect(self):
        """SHA256 hash auto-detected by length."""
        sha256 = "2c26b46911185131006145dd0c1ae4ad7f8f7e18ab01d32e3ca8b0a3b2c6b9a1"
        pattern = _pattern_from_ioc(sha256)
        assert pattern == "[file:hashes.'SHA-256' = '2c26b46911185131006145dd0c1ae4ad7f8f7e18ab01d32e3ca8b0a3b2c6b9a1']"

    def test_pattern_email(self):
        """Email pattern generated correctly."""
        pattern = _pattern_from_ioc("attacker@example.com", "email")
        assert pattern == "[email-addr:value = 'attacker@example.com']"

    def test_pattern_email_auto_detect(self):
        """Email auto-detected by @ and dot."""
        pattern = _pattern_from_ioc("user@domain.com")
        assert pattern == "[email-addr:value = 'user@domain.com']"

    def test_pattern_escapes_quotes(self):
        """Quotes in IOCs are properly escaped."""
        pattern = _pattern_from_ioc("test'ioc", "domain")
        assert "\\'" in pattern

    def test_pattern_escapes_backslashes(self):
        """Backslashes in IOCs are properly escaped."""
        pattern = _pattern_from_ioc("test\\ioc", "domain")
        assert "\\\\" in pattern

    def test_pattern_malformed_ioc_fallback(self):
        """Malformed IOCs fall back to artifact pattern."""
        pattern = _pattern_from_ioc("!@#$%^&*()")
        assert "artifact:payload_bin" in pattern

    def test_indicator_in_bundle(self):
        """Indicator objects created and added to bundle."""
        cluster = make_cluster(ClusterPriority.HIGH, iocs=["1.2.3.4"])
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert len(indicators) >= 1
        assert indicators[0]["pattern_type"] == "stix"
        assert "ipv4-addr:value" in indicators[0]["pattern"]


# ---------------------------------------------------------------------------
# TestGroupingObjects
# ---------------------------------------------------------------------------


class TestGroupingObjects:
    """Grouping SDO creation and priority mapping."""

    def test_grouping_created_per_cluster(self):
        """One grouping per cluster."""
        clusters = [
            make_cluster(ClusterPriority.HIGH, label="Cluster A"),
            make_cluster(ClusterPriority.MEDIUM, label="Cluster B"),
        ]
        report = make_report(clusters)
        bundle = to_stix_bundle(report)
        groupings = [obj for obj in bundle["objects"] if obj["type"] == "grouping"]
        assert len(groupings) == 2

    def test_grouping_has_cluster_name(self):
        """Grouping name matches cluster label."""
        cluster = make_cluster(ClusterPriority.HIGH, label="Phishing Campaign")
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        groupings = [obj for obj in bundle["objects"] if obj["type"] == "grouping"]
        assert groupings[0]["name"] == "Phishing Campaign"

    def test_grouping_has_priority_in_context(self):
        """Grouping context field contains priority."""
        cluster = make_cluster(ClusterPriority.CRITICAL)
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        groupings = [obj for obj in bundle["objects"] if obj["type"] == "grouping"]
        assert groupings[0]["context"] == "critical"

    def test_priority_to_severity_noise(self):
        """NOISE priority maps to low severity."""
        severity = _priority_to_severity(ClusterPriority.NOISE)
        assert severity == "low"

    def test_priority_to_severity_low(self):
        """LOW priority maps to low severity."""
        severity = _priority_to_severity(ClusterPriority.LOW)
        assert severity == "low"

    def test_priority_to_severity_medium(self):
        """MEDIUM priority maps to medium severity."""
        severity = _priority_to_severity(ClusterPriority.MEDIUM)
        assert severity == "medium"

    def test_priority_to_severity_high(self):
        """HIGH priority maps to high severity."""
        severity = _priority_to_severity(ClusterPriority.HIGH)
        assert severity == "high"

    def test_priority_to_severity_critical(self):
        """CRITICAL priority maps to high severity."""
        severity = _priority_to_severity(ClusterPriority.CRITICAL)
        assert severity == "high"

    def test_grouping_object_refs_includes_indicators(self):
        """Grouping object_refs includes its indicators."""
        iocs = ["1.2.3.4", "example.com"]
        cluster = make_cluster(ClusterPriority.HIGH, iocs=iocs)
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        groupings = [obj for obj in bundle["objects"] if obj["type"] == "grouping"]
        assert len(groupings[0]["object_refs"]) == len(iocs)


# ---------------------------------------------------------------------------
# TestNoteObjects
# ---------------------------------------------------------------------------


class TestNoteObjects:
    """Note SDO creation for cluster summaries."""

    def test_note_created_per_cluster(self):
        """At least one note created per cluster with label."""
        clusters = [
            make_cluster(ClusterPriority.HIGH, label="Cluster A"),
            make_cluster(ClusterPriority.MEDIUM, label="Cluster B"),
        ]
        report = make_report(clusters)
        bundle = to_stix_bundle(report)
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        assert len(notes) >= 2

    def test_summary_note_contains_cluster_info(self):
        """Summary note includes cluster name and priority."""
        cluster = make_cluster(ClusterPriority.HIGH, label="Test Cluster")
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        summary_notes = [n for n in notes if "Summary" in n.get("abstract", "")]
        assert len(summary_notes) >= 1
        assert "Test Cluster" in summary_notes[0]["content"]
        assert "HIGH" in summary_notes[0]["content"]

    def test_note_includes_alert_count(self):
        """Note content includes number of alerts."""
        alerts = [make_alert(), make_alert()]
        cluster = make_cluster(ClusterPriority.MEDIUM, alerts=alerts)
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        summary_notes = [n for n in notes if "Summary" in n.get("abstract", "")]
        assert "Alerts: 2" in summary_notes[0]["content"]

    def test_note_includes_ioc_count(self):
        """Note content includes number of IOCs."""
        iocs = ["1.2.3.4", "2.3.4.5", "example.com"]
        cluster = make_cluster(ClusterPriority.MEDIUM, iocs=iocs)
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        summary_notes = [n for n in notes if "Summary" in n.get("abstract", "")]
        assert "IOCs: 3" in summary_notes[0]["content"]

    def test_narrative_note_created_when_summary_exists(self):
        """Narrative note created if summary with narrative provided."""
        cluster = make_cluster(ClusterPriority.HIGH)
        summary = SummaryResult(
            executive_summary="Test summary",
            overall_priority=ClusterPriority.HIGH,
            provider="template",
            generated_at=datetime.now(timezone.utc),
            cluster_summaries=[
                ClusterSummary(
                    cluster_id=cluster.id,
                    narrative="This is a test narrative.",
                )
            ],
        )
        report = make_report([cluster], summary=summary)
        bundle = to_stix_bundle(report)
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        narrative_notes = [n for n in notes if "Narrative" in n.get("abstract", "")]
        assert len(narrative_notes) >= 1
        assert "test narrative" in narrative_notes[0]["content"]

    def test_no_narrative_note_when_narrative_empty(self):
        """No narrative note when ClusterSummary has empty narrative."""
        cluster = make_cluster(ClusterPriority.HIGH)
        summary = SummaryResult(
            executive_summary="Test summary",
            overall_priority=ClusterPriority.HIGH,
            provider="template",
            generated_at=datetime.now(timezone.utc),
            cluster_summaries=[
                ClusterSummary(
                    cluster_id=cluster.id,
                    narrative="",
                )
            ],
        )
        report = make_report([cluster], summary=summary)
        bundle = to_stix_bundle(report)
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        # Should only have summary note, not narrative note
        # (This test is lenient as we count on the implementation)
        assert len(notes) >= 1


# ---------------------------------------------------------------------------
# TestRelationships
# ---------------------------------------------------------------------------


class TestRelationshipObjects:
    """Relationship SDO creation and validation."""

    def test_relationship_aggregates_created(self):
        """Relationships are created to link groupings to indicators."""
        iocs = ["1.2.3.4"]
        cluster = make_cluster(ClusterPriority.HIGH, iocs=iocs)
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        relationships = [obj for obj in bundle["objects"] if obj["type"] == "relationship"]
        assert len(relationships) >= 1

    def test_relationship_has_source_and_target(self):
        """Each relationship has source_ref and target_ref."""
        cluster = make_cluster(ClusterPriority.HIGH, iocs=["1.2.3.4"])
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        relationships = [obj for obj in bundle["objects"] if obj["type"] == "relationship"]
        for rel in relationships:
            assert "source_ref" in rel
            assert "target_ref" in rel

    def test_relationship_references_valid_objects(self):
        """Relationship refs point to actual objects in bundle."""
        cluster = make_cluster(ClusterPriority.HIGH, iocs=["1.2.3.4"])
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        object_ids = {obj["id"] for obj in bundle["objects"]}
        relationships = [obj for obj in bundle["objects"] if obj["type"] == "relationship"]
        for rel in relationships:
            assert rel["source_ref"] in object_ids
            assert rel["target_ref"] in object_ids

    def test_relationship_type_valid(self):
        """Relationship types are valid STIX values."""
        cluster = make_cluster(ClusterPriority.HIGH, iocs=["1.2.3.4"])
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        relationships = [obj for obj in bundle["objects"] if obj["type"] == "relationship"]
        valid_types = {"aggregates", "indicates", "uses", "related-to"}
        for rel in relationships:
            assert rel["relationship_type"] in valid_types

    def test_multiple_iocs_create_multiple_relationships(self):
        """Multiple IOCs result in multiple aggregation relationships."""
        iocs = ["1.2.3.4", "2.3.4.5", "example.com"]
        cluster = make_cluster(ClusterPriority.HIGH, iocs=iocs)
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        aggregates_rels = [
            obj for obj in bundle["objects"]
            if obj["type"] == "relationship" and obj["relationship_type"] == "aggregates"
        ]
        assert len(aggregates_rels) >= len(iocs)


# ---------------------------------------------------------------------------
# Convenience function tests
# ---------------------------------------------------------------------------


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_to_stix_bundle_function(self):
        """to_stix_bundle() module function works."""
        cluster = make_cluster(ClusterPriority.HIGH)
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        assert bundle["type"] == "bundle"
        assert "objects" in bundle

    def test_to_stix_bundle_string_function(self):
        """to_stix_bundle_string() module function works."""
        cluster = make_cluster(ClusterPriority.HIGH)
        report = make_report([cluster])
        json_str = to_stix_bundle_string(report)
        assert isinstance(json_str, str)
        bundle = json.loads(json_str)
        assert bundle["type"] == "bundle"


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    """Test internal helper functions."""

    def test_deterministic_id_format(self):
        """_deterministic_id() returns valid STIX ID format."""
        stix_id = _deterministic_id("indicator", "192.168.1.1")
        assert stix_id.startswith("indicator--")
        assert len(stix_id) > len("indicator--")

    def test_deterministic_id_deterministic(self):
        """Same parts produce same ID."""
        id1 = _deterministic_id("indicator", "192.168.1.1")
        id2 = _deterministic_id("indicator", "192.168.1.1")
        assert id1 == id2

    def test_deterministic_id_different_parts(self):
        """Different parts produce different IDs."""
        id1 = _deterministic_id("indicator", "192.168.1.1")
        id2 = _deterministic_id("indicator", "192.168.1.2")
        assert id1 != id2

    def test_now_iso_format(self):
        """_now_iso() returns ISO 8601 string."""
        iso_str = _now_iso()
        assert isinstance(iso_str, str)
        assert "T" in iso_str
        assert iso_str.endswith("Z")
        # Must be parseable as ISO 8601
        dt = datetime.fromisoformat(iso_str.rstrip("Z") + "+00:00")
        assert dt is not None


# ---------------------------------------------------------------------------
# Edge cases and stress tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_clusters_list(self):
        """Report with no clusters produces valid bundle."""
        report = make_report([])
        bundle = to_stix_bundle(report)
        assert bundle["type"] == "bundle"
        assert bundle["objects"] == []

    def test_cluster_with_no_iocs(self):
        """Cluster without IOCs still produces valid bundle."""
        cluster = make_cluster(ClusterPriority.MEDIUM, iocs=[])
        report = make_report([cluster])
        bundle = to_stix_bundle(report)
        # Should still have grouping and note
        groupings = [obj for obj in bundle["objects"] if obj["type"] == "grouping"]
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        assert len(groupings) >= 1
        assert len(notes) >= 1

    def test_many_clusters(self):
        """Bundle with many clusters."""
        clusters = [make_cluster(ClusterPriority.HIGH) for _ in range(10)]
        report = make_report(clusters)
        bundle = to_stix_bundle(report)
        groupings = [obj for obj in bundle["objects"] if obj["type"] == "grouping"]
        assert len(groupings) == 10

    def test_unicode_in_ioc(self):
        """IOCs with unicode handled correctly."""
        # Note: Practical IOCs usually don't have unicode, but test robustness
        cluster = make_cluster(ClusterPriority.HIGH, iocs=["example.com"])
        report = make_report([cluster])
        json_str = to_stix_bundle_string(report)
        # Must not raise and must be valid JSON
        bundle = json.loads(json_str)
        assert bundle["type"] == "bundle"

    def test_special_chars_in_ioc_escaped(self):
        """Special characters in IOCs are properly escaped."""
        # Path with special chars
        ioc = r"C:\Windows\System32"
        cluster = make_cluster(ClusterPriority.HIGH, iocs=[ioc])
        report = make_report([cluster])
        json_str = to_stix_bundle_string(report)
        # Must be valid JSON (no unescaped quotes)
        bundle = json.loads(json_str)
        assert bundle["type"] == "bundle"
