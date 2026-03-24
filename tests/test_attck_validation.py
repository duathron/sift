"""Tests for MITRE ATT&CK technique ID validation."""

from __future__ import annotations

import logging

import pytest

from sift.pipeline.attck import (
    TECHNIQUE_PATTERN,
    is_valid_technique_id,
    normalize_technique_id,
    validate_technique_ids,
)


class TestIsValidTechniqueId:
    def test_valid_t1566(self):
        assert is_valid_technique_id("T1566") is True

    def test_valid_subtechnique(self):
        assert is_valid_technique_id("T1566.001") is True

    def test_valid_low_number(self):
        assert is_valid_technique_id("T0001") is True

    def test_invalid_all_letters(self):
        assert is_valid_technique_id("TXXXX") is False

    def test_invalid_no_t_prefix(self):
        assert is_valid_technique_id("1566") is False

    def test_invalid_too_many_digits(self):
        assert is_valid_technique_id("T12345") is False

    def test_invalid_empty_string(self):
        assert is_valid_technique_id("") is False

    def test_invalid_lowercase(self):
        assert is_valid_technique_id("t1566") is False

    def test_invalid_three_digit_base(self):
        assert is_valid_technique_id("T156") is False


class TestValidateTechniqueIds:
    def test_filters_out_invalid(self):
        result = validate_technique_ids(["T1566", "INVALID", "T1059.001"])
        assert result == ["T1566", "T1059.001"]

    def test_logs_warning_for_invalid(self, caplog):
        with caplog.at_level(logging.WARNING, logger="sift.pipeline.attck"):
            validate_technique_ids(["BAD_ID"])
        assert "BAD_ID" in caplog.text

    def test_empty_list(self):
        assert validate_technique_ids([]) == []

    def test_all_valid(self):
        ids = ["T1566", "T1059", "T1078.003"]
        assert validate_technique_ids(ids) == ids

    def test_all_invalid_returns_empty(self):
        result = validate_technique_ids(["bad1", "bad2", "T99999"])
        assert result == []


class TestNormalizeTechniqueId:
    def test_strips_whitespace(self):
        assert normalize_technique_id(" T1566 ") == "T1566"

    def test_uppercases(self):
        assert normalize_technique_id("t1566") == "T1566"

    def test_strips_and_uppercases(self):
        assert normalize_technique_id(" t1566.001 ") == "T1566.001"


class TestClustererIntegration:
    def test_clusterer_ignores_invalid_technique_ids(self):
        """Clusters from alerts with invalid technique IDs must not contain them."""
        from datetime import datetime, timezone

        from sift.models import Alert, AlertSeverity
        from sift.pipeline.clusterer import cluster_alerts

        alert = Alert(
            id="a1",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            category="malware",
            technique_ids=["T1566", "INVALID_ID", "T1059.001"],
        )
        clusters = cluster_alerts([alert])
        assert len(clusters) == 1
        technique_ids = [t.technique_id for t in clusters[0].techniques]
        assert "T1566" in technique_ids
        assert "T1059.001" in technique_ids
        assert "INVALID_ID" not in technique_ids

    def test_clusterer_empty_technique_ids(self):
        """Alerts with no technique_ids produce clusters with no techniques."""
        from datetime import datetime, timezone

        from sift.models import Alert, AlertSeverity
        from sift.pipeline.clusterer import cluster_alerts

        alert = Alert(
            id="a2",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.LOW,
            title="No Techniques",
        )
        clusters = cluster_alerts([alert])
        assert clusters[0].techniques == []
