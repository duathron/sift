"""Tests for sift.filtering: FilterParser, AlertFilter, and DSL evaluation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from sift.filtering import (
    FilterEvalError,
    FilterParser,
    FilterSyntaxError,
)
from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(
    category: str | None = None,
    severity: AlertSeverity = AlertSeverity.MEDIUM,
) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Test Alert",
        severity=severity,
        category=category,
    )


def make_cluster(
    priority: ClusterPriority = ClusterPriority.MEDIUM,
    category: str | None = None,
    num_alerts: int = 1,
    num_iocs: int = 0,
    confidence: float = 1.0,
) -> Cluster:
    alerts = [make_alert(category=category if i == 0 else None) for i in range(num_alerts)]
    iocs = [f"ioc_{i}" for i in range(num_iocs)]
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=alerts,
        priority=priority,
        score=0.0,
        confidence=confidence,
        iocs=iocs,
    )


# ---------------------------------------------------------------------------
# Test FilterParsing
# ---------------------------------------------------------------------------


class TestFilterParsing:
    """Test filter parsing and syntax validation."""

    def test_parse_simple_comparison(self):
        """Valid comparison should parse without error."""
        filt = FilterParser.parse("priority >= HIGH")
        assert filt is not None
        assert filt.query == "priority >= HIGH"

    def test_parse_set_membership(self):
        """Valid IN expression should parse."""
        filt = FilterParser.parse("category IN (malware, phishing)")
        assert filt is not None

    def test_parse_with_whitespace(self):
        """Extra whitespace should be handled."""
        filt = FilterParser.parse("  priority   >=   HIGH  ")
        assert filt is not None

    def test_parse_case_insensitive_keywords(self):
        """Keywords should be case-insensitive."""
        filt1 = FilterParser.parse("priority >= HIGH AND category IN (test)")
        filt2 = FilterParser.parse("PRIORITY >= HIGH and CATEGORY in (test)")
        assert filt1 is not None
        assert filt2 is not None

    def test_invalid_syntax_missing_value(self):
        """Missing value should raise FilterSyntaxError."""
        with pytest.raises(FilterSyntaxError):
            FilterParser.parse("priority >=")

    def test_invalid_syntax_unknown_operator(self):
        """Unknown operator should raise FilterSyntaxError."""
        with pytest.raises(FilterSyntaxError):
            FilterParser.parse("priority >> HIGH")


# ---------------------------------------------------------------------------
# Test Comparisons
# ---------------------------------------------------------------------------


class TestComparisons:
    """Test comparison operators against cluster properties."""

    def test_priority_equality(self):
        """priority == HIGH should match HIGH priority cluster."""
        cluster = make_cluster(priority=ClusterPriority.HIGH)
        filt = FilterParser.parse("priority == HIGH")
        assert filt.matches(cluster)

    def test_priority_equality_mismatch(self):
        """priority == HIGH should not match MEDIUM cluster."""
        cluster = make_cluster(priority=ClusterPriority.MEDIUM)
        filt = FilterParser.parse("priority == HIGH")
        assert not filt.matches(cluster)

    def test_priority_greater_than_or_equal(self):
        """priority >= MEDIUM should match MEDIUM and HIGH."""
        cluster_medium = make_cluster(priority=ClusterPriority.MEDIUM)
        cluster_high = make_cluster(priority=ClusterPriority.HIGH)
        cluster_low = make_cluster(priority=ClusterPriority.LOW)

        filt = FilterParser.parse("priority >= MEDIUM")
        assert filt.matches(cluster_medium)
        assert filt.matches(cluster_high)
        assert not filt.matches(cluster_low)

    def test_ioc_count_numeric(self):
        """ioc_count > 5 should match clusters with > 5 IOCs."""
        cluster_5 = make_cluster(num_iocs=5)
        cluster_6 = make_cluster(num_iocs=6)
        cluster_3 = make_cluster(num_iocs=3)

        filt = FilterParser.parse("ioc_count > 5")
        assert not filt.matches(cluster_5)
        assert filt.matches(cluster_6)
        assert not filt.matches(cluster_3)

    def test_alert_count_less_than_or_equal(self):
        """alert_count <= 3 should match clusters with <= 3 alerts."""
        cluster_2 = make_cluster(num_alerts=2)
        cluster_3 = make_cluster(num_alerts=3)
        cluster_4 = make_cluster(num_alerts=4)

        filt = FilterParser.parse("alert_count <= 3")
        assert filt.matches(cluster_2)
        assert filt.matches(cluster_3)
        assert not filt.matches(cluster_4)

    def test_confidence_score_numeric(self):
        """confidence_score >= 0.8 should match high-confidence clusters."""
        cluster_high = make_cluster(confidence=0.95)
        cluster_medium = make_cluster(confidence=0.80)
        cluster_low = make_cluster(confidence=0.5)

        filt = FilterParser.parse("confidence_score >= 0.8")
        assert filt.matches(cluster_high)
        assert filt.matches(cluster_medium)
        assert not filt.matches(cluster_low)

    def test_type_mismatch_error(self):
        """Comparing incompatible types should raise FilterEvalError."""
        cluster = make_cluster(priority=ClusterPriority.HIGH)
        filt = FilterParser.parse("priority > 5")
        with pytest.raises(FilterEvalError):
            filt.matches(cluster)


# ---------------------------------------------------------------------------
# Test Set Membership
# ---------------------------------------------------------------------------


class TestSetMembership:
    """Test IN and NOT IN operators."""

    def test_category_in_single_value(self):
        """category IN (malware) should match malware clusters."""
        cluster = make_cluster(category="malware")
        filt = FilterParser.parse("category IN (malware)")
        assert filt.matches(cluster)

    def test_category_in_multiple_values(self):
        """category IN (malware, phishing) should match either."""
        cluster_malware = make_cluster(category="malware")
        cluster_phishing = make_cluster(category="phishing")
        cluster_other = make_cluster(category="suspicious")

        filt = FilterParser.parse("category IN (malware, phishing)")
        assert filt.matches(cluster_malware)
        assert filt.matches(cluster_phishing)
        assert not filt.matches(cluster_other)

    def test_category_not_in(self):
        """category NOT IN (false_positive) should match non-FP categories."""
        cluster_fp = make_cluster(category="false_positive")
        cluster_malware = make_cluster(category="malware")

        filt = FilterParser.parse("category NOT IN (false_positive)")
        assert not filt.matches(cluster_fp)
        assert filt.matches(cluster_malware)

    def test_category_case_insensitive(self):
        """Category comparison should be case-insensitive."""
        cluster = make_cluster(category="Malware")
        filt = FilterParser.parse("category IN (malware, phishing)")
        assert filt.matches(cluster)

    def test_empty_category(self):
        """Clusters with no category should not match."""
        cluster = make_cluster(category=None)
        filt = FilterParser.parse("category IN (malware)")
        assert not filt.matches(cluster)


# ---------------------------------------------------------------------------
# Test Boolean Logic
# ---------------------------------------------------------------------------


class TestBooleanLogic:
    """Test AND, OR, NOT operators and precedence."""

    def test_and_operator(self):
        """priority >= HIGH AND category IN (malware) should require both."""
        high_malware = make_cluster(priority=ClusterPriority.HIGH, category="malware")
        high_other = make_cluster(priority=ClusterPriority.HIGH, category="phishing")
        low_malware = make_cluster(priority=ClusterPriority.LOW, category="malware")

        filt = FilterParser.parse("priority >= HIGH AND category IN (malware)")
        assert filt.matches(high_malware)
        assert not filt.matches(high_other)
        assert not filt.matches(low_malware)

    def test_or_operator(self):
        """priority == CRITICAL OR ioc_count > 10 should match either."""
        critical_few_iocs = make_cluster(priority=ClusterPriority.CRITICAL, num_iocs=5)
        low_many_iocs = make_cluster(priority=ClusterPriority.LOW, num_iocs=15)
        low_few_iocs = make_cluster(priority=ClusterPriority.LOW, num_iocs=5)

        filt = FilterParser.parse("priority == CRITICAL OR ioc_count > 10")
        assert filt.matches(critical_few_iocs)
        assert filt.matches(low_many_iocs)
        assert not filt.matches(low_few_iocs)

    def test_not_operator(self):
        """NOT priority == NOISE should match non-NOISE clusters."""
        noise = make_cluster(priority=ClusterPriority.NOISE)
        high = make_cluster(priority=ClusterPriority.HIGH)

        filt = FilterParser.parse("NOT priority == NOISE")
        assert not filt.matches(noise)
        assert filt.matches(high)

    def test_not_in_operator(self):
        """NOT category IN (false_positive) is same as category NOT IN."""
        fp = make_cluster(category="false_positive")
        malware = make_cluster(category="malware")

        filt = FilterParser.parse("NOT category IN (false_positive)")
        assert not filt.matches(fp)
        assert filt.matches(malware)

    def test_and_precedence_over_or(self):
        """AND should bind tighter than OR: A OR B AND C = A OR (B AND C)."""
        # priority == CRITICAL OR (ioc_count > 10 AND alert_count <= 3)
        critical_many_alerts = make_cluster(priority=ClusterPriority.CRITICAL, num_iocs=0, num_alerts=10)
        low_many_iocs_few_alerts = make_cluster(priority=ClusterPriority.LOW, num_iocs=15, num_alerts=2)
        low_many_iocs_many_alerts = make_cluster(priority=ClusterPriority.LOW, num_iocs=15, num_alerts=5)

        filt = FilterParser.parse("priority == CRITICAL OR ioc_count > 10 AND alert_count <= 3")
        assert filt.matches(critical_many_alerts)
        assert filt.matches(low_many_iocs_few_alerts)
        assert not filt.matches(low_many_iocs_many_alerts)

    def test_parentheses_override_precedence(self):
        """Parentheses should override precedence: (A OR B) AND C."""
        # (priority == CRITICAL OR category IN (malware)) AND ioc_count > 5
        critical_few_iocs = make_cluster(priority=ClusterPriority.CRITICAL, num_iocs=3)
        critical_many_iocs = make_cluster(priority=ClusterPriority.CRITICAL, num_iocs=10)
        low_malware_few_iocs = make_cluster(priority=ClusterPriority.LOW, category="malware", num_iocs=3)
        low_malware_many_iocs = make_cluster(priority=ClusterPriority.LOW, category="malware", num_iocs=10)

        filt = FilterParser.parse("(priority == CRITICAL OR category IN (malware)) AND ioc_count > 5")
        assert not filt.matches(critical_few_iocs)
        assert filt.matches(critical_many_iocs)
        assert not filt.matches(low_malware_few_iocs)
        assert filt.matches(low_malware_many_iocs)

    def test_complex_expression(self):
        """Complex nested expression should evaluate correctly."""
        cluster = make_cluster(
            priority=ClusterPriority.HIGH,
            category="malware",
            num_iocs=8,
            num_alerts=2,
        )

        filt = FilterParser.parse(
            "NOT (priority == NOISE) AND (category IN (malware, phishing) OR ioc_count > 10) AND alert_count <= 3"
        )
        assert filt.matches(cluster)

    def test_priority_all_levels(self):
        """Test priority ordering: NOISE < LOW < MEDIUM < HIGH < CRITICAL."""
        for i, prio in enumerate([ClusterPriority.NOISE, ClusterPriority.LOW, ClusterPriority.MEDIUM,
                                   ClusterPriority.HIGH, ClusterPriority.CRITICAL]):
            cluster = make_cluster(priority=prio)

            # priority >= MEDIUM should match MEDIUM and above
            filt_ge = FilterParser.parse("priority >= MEDIUM")
            expected = i >= 2
            assert filt_ge.matches(cluster) == expected, f"Failed for {prio}"

            # priority < MEDIUM should match NOISE and LOW
            filt_lt = FilterParser.parse("priority < MEDIUM")
            expected_lt = i < 2
            assert filt_lt.matches(cluster) == expected_lt, f"Failed for {prio}"


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_zero_iocs(self):
        """Clusters with zero IOCs should work."""
        cluster = make_cluster(num_iocs=0)
        filt = FilterParser.parse("ioc_count == 0")
        assert filt.matches(cluster)

    def test_negative_ioc_comparison_never_matches(self):
        """ioc_count > -1 should match all (counts are >= 0)."""
        cluster = make_cluster(num_iocs=0)
        filt = FilterParser.parse("ioc_count > -1")
        assert filt.matches(cluster)

    def test_single_alert(self):
        """Single alert cluster should work."""
        cluster = make_cluster(num_alerts=1)
        filt = FilterParser.parse("alert_count == 1")
        assert filt.matches(cluster)

    def test_very_high_ioc_count(self):
        """Large ioc_count should work."""
        cluster = make_cluster(num_iocs=1000)
        filt = FilterParser.parse("ioc_count >= 1000")
        assert filt.matches(cluster)

    def test_confidence_boundary_zero(self):
        """confidence_score == 0.0 should match."""
        cluster = make_cluster(confidence=0.0)
        filt = FilterParser.parse("confidence_score == 0.0")
        assert filt.matches(cluster)

    def test_confidence_boundary_one(self):
        """confidence_score == 1.0 should match."""
        cluster = make_cluster(confidence=1.0)
        filt = FilterParser.parse("confidence_score == 1.0")
        assert filt.matches(cluster)

    def test_inequality_operator(self):
        """!= should work correctly."""
        cluster_medium = make_cluster(priority=ClusterPriority.MEDIUM)
        cluster_high = make_cluster(priority=ClusterPriority.HIGH)

        filt = FilterParser.parse("priority != MEDIUM")
        assert not filt.matches(cluster_medium)
        assert filt.matches(cluster_high)

    def test_less_than_operator(self):
        """< should work correctly."""
        cluster = make_cluster(num_iocs=5)
        filt = FilterParser.parse("ioc_count < 5")
        assert not filt.matches(cluster)

        cluster_small = make_cluster(num_iocs=4)
        assert filt.matches(cluster_small)

    def test_unknown_field(self):
        """Unknown field should raise FilterEvalError."""
        cluster = make_cluster()
        filt = FilterParser.parse("unknown_field > 5")
        with pytest.raises(FilterEvalError):
            filt.matches(cluster)

    def test_set_membership_only_for_category(self):
        """IN operator should only work with category field."""
        cluster = make_cluster(num_iocs=5)
        filt = FilterParser.parse("ioc_count IN (5)")
        with pytest.raises(FilterEvalError):
            filt.matches(cluster)
