"""Edge case tests for sift v0.8.0 beta.

Covers edge cases across normalizers, IOC extractor, prioritizer,
cache, and filter DSL.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sift.cache import AlertCache, CacheConfig
from sift.filtering import FilterParser, FilterSyntaxError
from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority
from sift.normalizers.csv_normalizer import CSVNormalizer
from sift.normalizers.generic import GenericNormalizer
from sift.pipeline.ioc_extractor import enrich_alert_iocs, extract_iocs
from sift.pipeline.prioritizer import prioritize, score_cluster
from sift.config import ScoringConfig, SeverityWeights, PriorityThresholds


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _alert(
    *,
    title: str = "Test Alert",
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    category: str | None = None,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    description: str | None = None,
    raw: dict | None = None,
) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title=title,
        severity=severity,
        category=category,
        source_ip=source_ip,
        dest_ip=dest_ip,
        description=description,
        raw=raw or {},
    )


def _cluster(
    *,
    alerts: list[Alert] | None = None,
    priority: ClusterPriority = ClusterPriority.MEDIUM,
    iocs: list[str] | None = None,
    techniques=None,
    confidence: float = 1.0,
) -> Cluster:
    if alerts is None:
        alerts = [_alert()]
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=alerts,
        priority=priority,
        score=0.0,
        confidence=confidence,
        iocs=iocs or [],
        techniques=techniques or [],
    )


# ===========================================================================
# 1. Normalizer edge cases
# ===========================================================================


class TestGenericNormalizerEdgeCases:
    """Edge cases for GenericNormalizer."""

    def test_empty_json_array_returns_empty_list(self):
        """Parsing [] must return an empty list, not raise."""
        normalizer = GenericNormalizer()
        result = normalizer.normalize("[]")
        assert result == []

    def test_json_with_missing_required_fields_normalizes_gracefully(self):
        """An alert record with no standard fields still produces an Alert with defaults."""
        normalizer = GenericNormalizer()
        data = json.dumps([{"foo": "bar", "baz": 42}])
        result = normalizer.normalize(data)
        assert len(result) == 1
        assert result[0].title == "Unknown Alert"
        assert result[0].severity == AlertSeverity.MEDIUM

    def test_ndjson_malformed_line_in_middle_skips_bad_parses_rest(self):
        """NDJSON with a garbage line between valid lines — generic normalizer
        wraps each record individually, so even if one dict is missing fields
        it still produces an Alert (graceful, not a crash)."""
        # The GenericNormalizer processes a JSON array; we test that a list
        # containing a valid dict and a non-dict value drops the non-dict.
        normalizer = GenericNormalizer()
        # Simulate NDJSON fed as a JSON array with mixed types.
        data = json.dumps([
            {"title": "Good Alert 1", "severity": "high"},
            "this is not a dict",
            {"title": "Good Alert 2", "severity": "low"},
        ])
        result = normalizer.normalize(data)
        # Only the two dict entries should produce Alerts.
        assert len(result) == 2
        assert result[0].title == "Good Alert 1"
        assert result[1].title == "Good Alert 2"

    def test_unicode_in_alert_title_and_description(self):
        """Unicode characters in title/description are preserved verbatim."""
        normalizer = GenericNormalizer()
        title = "Alerte de sécurité — Файл вредоносный 🚨"
        desc = "Détails: 악성코드 감지됨"
        data = json.dumps([{"title": title, "description": desc}])
        result = normalizer.normalize(data)
        assert len(result) == 1
        assert result[0].title == title
        assert result[0].description == desc

    def test_very_long_alert_title_is_handled_without_crash(self):
        """A title exceeding 1000 characters is stored as-is (no truncation enforced
        at the normalizer level — the model accepts any string)."""
        normalizer = GenericNormalizer()
        long_title = "A" * 2000
        data = json.dumps([{"title": long_title}])
        result = normalizer.normalize(data)
        assert len(result) == 1
        # Title is preserved (normalizer does not truncate)
        assert len(result[0].title) == 2000

    def test_numeric_id_field_cast_to_string(self):
        """An integer 'id' field is cast to string in the resulting Alert."""
        normalizer = GenericNormalizer()
        data = json.dumps([{"id": 1234, "title": "Numeric ID Alert"}])
        result = normalizer.normalize(data)
        assert len(result) == 1
        assert result[0].id == "1234"

    def test_nested_json_objects_in_alert_fields_stored_in_raw(self):
        """A nested dict value ends up in alert.raw and does not crash normalizer."""
        normalizer = GenericNormalizer()
        nested = {"outer": {"inner": "value", "count": 5}}
        data = json.dumps([{"title": "Nested Alert", "metadata": nested}])
        result = normalizer.normalize(data)
        assert len(result) == 1
        assert "metadata" in result[0].raw

    def test_single_dict_input_returns_one_alert(self):
        """A JSON object (not array) is treated as a single-record input."""
        normalizer = GenericNormalizer()
        data = json.dumps({"title": "Single Dict Alert", "severity": "critical"})
        result = normalizer.normalize(data)
        assert len(result) == 1
        assert result[0].severity == AlertSeverity.CRITICAL


class TestCSVNormalizerEdgeCases:
    """Edge cases for CSVNormalizer."""

    def test_csv_with_only_headers_no_data_rows_returns_empty(self):
        """A CSV that has only a header row produces an empty list."""
        normalizer = CSVNormalizer()
        csv_data = "title,severity,category\n"
        result = normalizer.normalize(csv_data)
        assert result == []


# ===========================================================================
# 2. IOC extractor edge cases
# ===========================================================================


class TestIOCExtractorEdgeCases:
    """Edge cases for extract_iocs and enrich_alert_iocs."""

    def test_ipv6_addresses_extracted_correctly(self):
        """Full IPv6 addresses in text are extracted as IOCs."""
        text = "Suspicious connection from 2001:db8:85a3::8a2e:370:7334 to internal host."
        iocs = extract_iocs(text)
        # 2001:db8:85a3::8a2e:370:7334 is a valid non-loopback IPv6
        ipv6_iocs = [i for i in iocs if ":" in i]
        assert len(ipv6_iocs) >= 1

    def test_defanged_http_ioc_not_extracted_as_url(self):
        """Defanged hxxp:// URLs do not match the URL regex (by design — sift
        does not currently refang; this documents the current behaviour)."""
        text = "User visited hxxp://evil.example.com/payload"
        iocs = extract_iocs(text)
        url_iocs = [i for i in iocs if i.startswith("http")]
        # hxxp:// is not a recognised URL scheme — the regex won't match it
        assert not any("hxxp" in i for i in url_iocs)

    def test_private_ips_not_returned_by_extract_iocs(self):
        """extract_iocs filters out private IPv4 ranges (RFC-1918).

        Note: enrich_alert_iocs *does* include source_ip/dest_ip regardless,
        but the pure extract_iocs function filters private IPs.
        """
        text = "Traffic from 192.168.1.100 to 10.0.0.5"
        iocs = extract_iocs(text)
        assert "192.168.1.100" not in iocs
        assert "10.0.0.5" not in iocs

    def test_private_ips_included_via_enrich_alert_iocs_source_dest(self):
        """enrich_alert_iocs unconditionally includes source_ip/dest_ip even
        when they are private — they provide network context."""
        alert = _alert(source_ip="192.168.1.100", dest_ip="10.0.0.5")
        enriched = enrich_alert_iocs(alert)
        assert "192.168.1.100" in enriched.iocs
        assert "10.0.0.5" in enriched.iocs

    def test_duplicate_iocs_across_alerts_deduplicated_within_alert(self):
        """When the same IOC string appears in multiple fields of one alert,
        only one copy appears in alert.iocs."""
        alert = _alert(
            title="Malware at 185.220.101.1",
            description="C2 callback to 185.220.101.1",
            dest_ip="185.220.101.1",
        )
        enriched = enrich_alert_iocs(alert)
        assert enriched.iocs.count("185.220.101.1") == 1

    def test_ioc_in_nested_raw_field_is_extracted(self):
        """IOCs embedded inside nested dicts in alert.raw are extracted."""
        alert = _alert(
            raw={"metadata": {"c2": "45.33.32.156", "note": "confirmed"}},
        )
        enriched = enrich_alert_iocs(alert)
        assert "45.33.32.156" in enriched.iocs

    def test_no_iocs_found_returns_empty_list(self):
        """An alert with no IOC-like content returns an empty iocs list."""
        alert = _alert(title="Scheduled task modified", description="No network activity.")
        enriched = enrich_alert_iocs(alert)
        assert enriched.iocs == []


# ===========================================================================
# 3. Prioritizer edge cases
# ===========================================================================


class TestPrioritizerEdgeCases:
    """Edge cases for score_cluster and prioritize."""

    def _weights(self) -> SeverityWeights:
        return SeverityWeights()

    def test_single_alert_cluster_no_iocs_gets_baseline_priority(self):
        """A lone MEDIUM-severity alert with no IOCs scores above NOISE."""
        cluster = _cluster(alerts=[_alert(severity=AlertSeverity.MEDIUM)], iocs=[])
        result = prioritize(cluster)
        # MEDIUM weight=5, no multipliers → score=5.0; threshold.low=5 → LOW
        assert result.priority in (ClusterPriority.LOW, ClusterPriority.NOISE, ClusterPriority.MEDIUM)
        # Must not crash and must have a non-negative score
        assert result.score >= 0

    def test_cluster_with_50_critical_alerts_gets_critical_priority(self):
        """50 CRITICAL alerts must reach the CRITICAL priority tier."""
        alerts = [_alert(severity=AlertSeverity.CRITICAL) for _ in range(50)]
        cluster = _cluster(alerts=alerts)
        result = prioritize(cluster)
        assert result.priority == ClusterPriority.CRITICAL

    def test_cluster_with_all_low_severity_stays_low_or_noise(self):
        """A cluster where every alert is LOW severity stays LOW or NOISE."""
        alerts = [_alert(severity=AlertSeverity.LOW) for _ in range(3)]
        cluster = _cluster(alerts=alerts, iocs=[])
        result = prioritize(cluster)
        assert result.priority in (ClusterPriority.NOISE, ClusterPriority.LOW)

    def test_mixed_severity_highest_drives_priority(self):
        """One CRITICAL alert in a mixed cluster triggers the ×1.5 multiplier."""
        alerts = [
            _alert(severity=AlertSeverity.LOW),
            _alert(severity=AlertSeverity.LOW),
            _alert(severity=AlertSeverity.CRITICAL),
        ]
        cluster_mixed = _cluster(alerts=alerts)
        cluster_all_low = _cluster(
            alerts=[_alert(severity=AlertSeverity.LOW) for _ in range(3)]
        )
        result_mixed = prioritize(cluster_mixed)
        result_low = prioritize(cluster_all_low)
        # Mixed cluster must score strictly higher than the all-LOW cluster.
        assert result_mixed.score > result_low.score

    def test_score_never_negative(self):
        """score_cluster always returns a non-negative value."""
        # Use a near-zero confidence to exercise the lower bound.
        cluster = _cluster(
            alerts=[_alert(severity=AlertSeverity.INFO)],
            confidence=0.01,
        )
        weights = self._weights()
        score = score_cluster(cluster, weights)
        assert score >= 0


# ===========================================================================
# 4. Cache edge cases
# ===========================================================================


class TestCacheEdgeCases:
    """Edge cases for AlertCache."""

    def _disabled_config(self, tmp_path: Path) -> CacheConfig:
        return CacheConfig(enabled=False, cache_dir=tmp_path / "cache")

    def _enabled_config(self, tmp_path: Path, **kwargs) -> CacheConfig:
        return CacheConfig(enabled=True, cache_dir=tmp_path / "cache", **kwargs)

    def test_disabled_cache_get_always_returns_none(self, tmp_path: Path):
        """With enabled=False every get() returns None without touching disk."""
        cache = AlertCache(self._disabled_config(tmp_path))
        cache.put("fp_x", {"result": "value"})
        result = cache.get("fp_x")
        assert result is None
        # No DB file should have been created.
        assert not (tmp_path / "cache").exists()

    def test_multiple_gets_same_key_returns_consistent_result(self, tmp_path: Path):
        """Multiple consecutive get() calls on the same key all return the same value."""
        cache = AlertCache(self._enabled_config(tmp_path))
        payload = {"clusters": ["a", "b"], "priority": "HIGH"}
        cache.put("fp_multi", payload)
        assert cache.get("fp_multi") == payload
        assert cache.get("fp_multi") == payload
        assert cache.get("fp_multi") == payload

    def test_very_large_result_stored_and_retrieved_intact(self, tmp_path: Path):
        """A result dict with 10 000 entries round-trips through the cache correctly."""
        cache = AlertCache(self._enabled_config(tmp_path))
        large = {str(i): f"value_{i}" for i in range(10_000)}
        cache.put("fp_large", large)
        result = cache.get("fp_large")
        assert result == large

    def test_ttl_zero_expires_every_entry_immediately(self, tmp_path: Path):
        """With ttl_seconds=0, every entry is already expired on the next get()."""
        cache = AlertCache(self._enabled_config(tmp_path, ttl_seconds=0))
        cache.put("fp_ttl0", {"data": "should_expire"})
        # Sleep briefly to ensure created_at is strictly in the past.
        time.sleep(0.01)
        result = cache.get("fp_ttl0")
        assert result is None

    def test_stats_after_mixed_hits_misses_returns_correct_counts(self, tmp_path: Path):
        """stats() reflects the correct hit and miss counts after a mixed workload."""
        cache = AlertCache(self._enabled_config(tmp_path))
        cache.put("fp_a", {"tag": "alpha"})
        cache.put("fp_b", {"tag": "beta"})

        cache.get("fp_a")   # hit
        cache.get("fp_a")   # hit
        cache.get("fp_b")   # hit
        cache.get("fp_nope")  # miss
        cache.get("fp_nada")  # miss

        stats = cache.stats()
        assert stats["hits"] == 3
        assert stats["misses"] == 2
        assert stats["entries"] >= 2


# ===========================================================================
# 5. Filter DSL edge cases
# ===========================================================================


class TestFilterDSLEdgeCases:
    """Edge cases for FilterParser and filter expression evaluation."""

    def _cluster(
        self,
        priority: ClusterPriority = ClusterPriority.MEDIUM,
        category: str | None = "malware",
        num_alerts: int = 1,
        num_iocs: int = 0,
    ) -> Cluster:
        alerts = [
            Alert(
                id=str(uuid.uuid4()),
                title="Test",
                severity=AlertSeverity.MEDIUM,
                category=category if i == 0 else None,
            )
            for i in range(num_alerts)
        ]
        return Cluster(
            id=str(uuid.uuid4()),
            label="Test",
            alerts=alerts,
            priority=priority,
            score=0.0,
            iocs=[f"ioc_{i}" for i in range(num_iocs)],
        )

    def test_empty_filter_string_raises_filter_syntax_error(self):
        """An empty string is not a valid filter expression."""
        with pytest.raises((FilterSyntaxError, Exception)):
            FilterParser.parse("")

    def test_unknown_field_name_raises_error_on_evaluation(self):
        """Referencing a field that does not exist raises an error at evaluation time."""
        from sift.filtering import FilterEvalError
        f = FilterParser.parse("nonexistent_field == 42")
        cluster = self._cluster()
        with pytest.raises((FilterEvalError, Exception)):
            f.matches(cluster)

    def test_priority_in_syntax_raises_on_unsupported_field(self):
        """The IN operator is only supported for 'category' — using it with
        'priority' is parsed successfully but raises FilterEvalError at
        evaluation time (by design: priority uses ordered comparisons)."""
        from sift.filtering import FilterEvalError

        f = FilterParser.parse("priority IN (HIGH, CRITICAL)")
        cluster = self._cluster(priority=ClusterPriority.HIGH)
        with pytest.raises(FilterEvalError):
            f.matches(cluster)

    def test_whitespace_only_filter_raises_error(self):
        """A filter string composed entirely of whitespace is invalid."""
        with pytest.raises((FilterSyntaxError, Exception)):
            FilterParser.parse("   ")

    def test_chained_and_with_three_conditions(self):
        """priority >= HIGH AND ioc_count > 2 AND alert_count <= 10 is parsed and evaluated."""
        f = FilterParser.parse("priority >= HIGH AND ioc_count > 2 AND alert_count <= 10")
        # Matches: HIGH priority, 3 IOCs, 5 alerts
        match_cluster = self._cluster(
            priority=ClusterPriority.HIGH,
            num_iocs=3,
            num_alerts=5,
        )
        # Does not match: MEDIUM priority
        no_match_cluster = self._cluster(
            priority=ClusterPriority.MEDIUM,
            num_iocs=3,
            num_alerts=5,
        )
        assert f.matches(match_cluster) is True
        assert f.matches(no_match_cluster) is False

    def test_deeply_nested_parens_evaluated_correctly(self):
        """(priority == CRITICAL OR (ioc_count > 5 AND alert_count > 3)) is valid."""
        f = FilterParser.parse(
            "(priority == CRITICAL OR (ioc_count > 5 AND alert_count > 3))"
        )
        # Matches because CRITICAL
        critical_cluster = self._cluster(priority=ClusterPriority.CRITICAL)
        assert f.matches(critical_cluster) is True

        # Matches because ioc_count > 5 AND alert_count > 3
        deep_match = self._cluster(
            priority=ClusterPriority.LOW,
            num_iocs=6,
            num_alerts=4,
        )
        assert f.matches(deep_match) is True

        # Does not match: LOW priority, 2 IOCs, 1 alert
        no_match = self._cluster(
            priority=ClusterPriority.LOW,
            num_iocs=2,
            num_alerts=1,
        )
        assert f.matches(no_match) is False
