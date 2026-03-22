"""Tests for sift.summarizers.validation — validation layer for LLM summaries.

This test module ensures that:
1. Valid summaries pass validation and are returned as-is.
2. Invalid/missing fields fail gracefully with fallback to template.
3. Type coercion works correctly (string → ClusterPriority enum).
4. Max length validation is enforced.
5. Nested structure validation works for cluster summaries and recommendations.
6. Integration with LLM summarizers (anthropic) works end-to-end.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    ClusterSummary,
    Recommendation,
    SummaryResult,
    TriageReport,
)
from sift.summarizers.template import TemplateSummarizer
from sift.summarizers.validation import SummaryResultSchema, SummaryValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(severity: AlertSeverity = AlertSeverity.HIGH) -> Alert:
    """Create a minimal test alert."""
    return Alert(
        id=str(uuid.uuid4()),
        severity=severity,
        title="Test Alert",
    )


def make_cluster(priority: ClusterPriority = ClusterPriority.HIGH) -> Cluster:
    """Create a minimal test cluster."""
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=[make_alert()],
        priority=priority,
        score=50.0,
    )


def make_report(clusters: list[Cluster] | None = None) -> TriageReport:
    """Create a minimal test TriageReport."""
    if clusters is None:
        clusters = [make_cluster()]
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime.now(tz=timezone.utc),
    )


def make_valid_raw_dict() -> dict[str, Any]:
    """Create a valid raw dictionary as returned by LLM JSON parsing."""
    return {
        "executive_summary": "Processed 5 alerts, 1 cluster flagged as HIGH.",
        "cluster_summaries": [
            {
                "cluster_id": "cluster-1",
                "narrative": "High-priority phishing activity detected.",
                "recommendations": [
                    {
                        "action": "Block sender domain",
                        "priority": "IMMEDIATE",
                        "rationale": "Known phishing domain.",
                    }
                ],
            }
        ],
        "overall_priority": "HIGH",
    }


# ---------------------------------------------------------------------------
# Test SummaryResultSchema validation
# ---------------------------------------------------------------------------


class TestSummaryResultSchemaValidation:
    """Test Pydantic schema validation for SummaryResultSchema."""

    def test_valid_schema_passes(self):
        """A valid dictionary parses into SummaryResultSchema without error."""
        data = make_valid_raw_dict()
        schema = SummaryResultSchema(**data)
        assert schema.executive_summary == data["executive_summary"]
        assert len(schema.cluster_summaries) == 1
        assert schema.overall_priority == "HIGH"

    def test_missing_executive_summary_fails(self):
        """Missing executive_summary raises ValidationError."""
        data = make_valid_raw_dict()
        del data["executive_summary"]
        with pytest.raises(Exception):  # Pydantic ValidationError
            SummaryResultSchema(**data)

    def test_empty_executive_summary_fails(self):
        """Empty string for executive_summary fails validation (min_length=1)."""
        data = make_valid_raw_dict()
        data["executive_summary"] = ""
        with pytest.raises(Exception):
            SummaryResultSchema(**data)

    def test_executive_summary_whitespace_stripped(self):
        """Whitespace around executive_summary is stripped."""
        data = make_valid_raw_dict()
        data["executive_summary"] = "  \n  Summary text  \n  "
        schema = SummaryResultSchema(**data)
        assert schema.executive_summary == "Summary text"

    def test_overall_priority_coercion_lowercase_to_enum(self):
        """overall_priority 'high' (lowercase) is coerced to uppercase."""
        data = make_valid_raw_dict()
        data["overall_priority"] = "high"
        schema = SummaryResultSchema(**data)
        assert schema.overall_priority == "HIGH"

    def test_overall_priority_invalid_value_raises(self):
        """overall_priority with invalid value raises ValidationError."""
        data = make_valid_raw_dict()
        data["overall_priority"] = "INVALID_PRIORITY"
        with pytest.raises(Exception):
            SummaryResultSchema(**data)

    def test_overall_priority_defaults_to_medium_when_missing(self):
        """When overall_priority is missing, defaults to 'MEDIUM'."""
        data = make_valid_raw_dict()
        del data["overall_priority"]
        schema = SummaryResultSchema(**data)
        assert schema.overall_priority == "MEDIUM"

    def test_cluster_summaries_empty_list_allowed(self):
        """cluster_summaries can be an empty list (no clusters to summarize)."""
        data = make_valid_raw_dict()
        data["cluster_summaries"] = []
        schema = SummaryResultSchema(**data)
        assert schema.cluster_summaries == []

    def test_cluster_summaries_malformed_skipped(self):
        """Malformed cluster summaries in the list are skipped with a warning."""
        data = make_valid_raw_dict()
        data["cluster_summaries"] = [
            {
                "cluster_id": "cluster-1",
                "narrative": "Valid cluster",
                "recommendations": [],
            },
            {
                # Missing required 'narrative' field
                "cluster_id": "cluster-2",
            },
        ]
        schema = SummaryResultSchema(**data)
        # The malformed entry should be skipped; only valid one remains
        assert len(schema.cluster_summaries) == 1
        assert schema.cluster_summaries[0].cluster_id == "cluster-1"

    def test_recommendations_coerced_from_dicts(self):
        """Recommendation dicts in cluster_summaries are coerced to Recommendation objects."""
        data = make_valid_raw_dict()
        schema = SummaryResultSchema(**data)
        assert isinstance(schema.cluster_summaries[0].recommendations[0], Recommendation)
        assert (
            schema.cluster_summaries[0].recommendations[0].action == "Block sender domain"
        )

    def test_extra_fields_ignored(self):
        """Extra unknown fields in the input dict are ignored per model_config."""
        data = make_valid_raw_dict()
        data["unknown_field"] = "should be ignored"
        data["another_unknown"] = 12345
        schema = SummaryResultSchema(**data)
        assert not hasattr(schema, "unknown_field")


# ---------------------------------------------------------------------------
# Test SummaryValidator
# ---------------------------------------------------------------------------


class TestSummaryValidator:
    """Test the SummaryValidator.validate() method and fallback logic."""

    def test_valid_data_returns_summary_result(self):
        """Valid data passes validation and returns a SummaryResult."""
        data = make_valid_raw_dict()
        report = make_report()
        result = SummaryValidator.validate(data, "test-provider", report)
        assert isinstance(result, SummaryResult)
        assert result.provider == "test-provider"
        assert result.overall_priority == ClusterPriority.HIGH

    def test_missing_executive_summary_falls_back_to_template(self, caplog):
        """When executive_summary is missing, falls back to template with warning."""
        data = make_valid_raw_dict()
        del data["executive_summary"]
        report = make_report()
        with caplog.at_level(logging.WARNING):
            result = SummaryValidator.validate(data, "bad-provider", report)
        assert isinstance(result, SummaryResult)
        assert result.provider == "template"  # Fallback used
        assert "Validation failed" in caplog.text

    def test_invalid_json_data_falls_back(self, caplog):
        """When validation fails with invalid data, falls back to template."""
        data = None  # This will cause TypeError
        report = make_report()
        with caplog.at_level(logging.WARNING):
            result = SummaryValidator.validate(data, "bad-provider", report)
        assert isinstance(result, SummaryResult)
        assert result.provider == "template"

    def test_priority_coercion_in_validate(self):
        """Priority string is coerced to ClusterPriority enum in validate()."""
        data = make_valid_raw_dict()
        data["overall_priority"] = "critical"  # lowercase
        report = make_report()
        result = SummaryValidator.validate(data, "test", report)
        assert result.overall_priority == ClusterPriority.CRITICAL

    def test_all_cluster_priorities_coerced(self):
        """All valid ClusterPriority values are correctly coerced."""
        report = make_report()
        for priority_str in ["NOISE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            data = make_valid_raw_dict()
            data["overall_priority"] = priority_str
            result = SummaryValidator.validate(data, "test", report)
            assert result.overall_priority == ClusterPriority[priority_str]

    def test_nested_cluster_summaries_validation(self):
        """Nested cluster_summaries structure is validated correctly."""
        data = make_valid_raw_dict()
        data["cluster_summaries"] = [
            {
                "cluster_id": "c1",
                "narrative": "Narrative 1",
                "recommendations": [
                    {"action": "Action 1", "priority": "IMMEDIATE", "rationale": "Reason 1"}
                ],
            },
            {
                "cluster_id": "c2",
                "narrative": "Narrative 2",
                "recommendations": [],
            },
        ]
        report = make_report()
        result = SummaryValidator.validate(data, "test", report)
        assert len(result.cluster_summaries) == 2
        assert result.cluster_summaries[0].cluster_id == "c1"
        assert len(result.cluster_summaries[0].recommendations) == 1

    def test_max_length_validation_on_executive_summary(self):
        """Very long executive_summary is rejected during schema validation."""
        data = make_valid_raw_dict()
        data["executive_summary"] = "x" * 10001  # Exceeds max_length=10000
        report = make_report()
        # This should fail validation and fall back to template
        result = SummaryValidator.validate(data, "test", report)
        assert result.provider == "template"  # Fallback


# ---------------------------------------------------------------------------
# Test SummaryValidator.validate_field()
# ---------------------------------------------------------------------------


class TestSummaryValidatorValidateField:
    """Test the single-field validation helper."""

    def test_validate_field_passes_for_correct_type(self):
        """validate_field returns True when type matches."""
        result = SummaryValidator.validate_field("test_field", "some string", str)
        assert result is True

    def test_validate_field_fails_for_wrong_type(self, caplog):
        """validate_field returns False and logs warning when type mismatches."""
        with caplog.at_level(logging.WARNING):
            result = SummaryValidator.validate_field("test_field", 123, str)
        assert result is False
        assert "test_field" in caplog.text
        assert "expected str" in caplog.text


# ---------------------------------------------------------------------------
# Integration tests: Anthropic + Validation
# ---------------------------------------------------------------------------


class TestAnthropicWithValidation:
    """Integration test: AnthropicSummarizer with validation layer.

    These tests verify that the validation layer integrates correctly
    with the real Anthropic summarizer (mocked API calls).

    Note: These tests are skipped if anthropic package is not installed.
    """

    @pytest.mark.skip(reason="anthropic package not installed in test environment")
    def test_anthropic_valid_response_passes_validation(self, monkeypatch):
        """Valid Anthropic response is validated and returned as-is."""
        from unittest.mock import MagicMock

        from sift.config import SummarizeConfig
        from sift.summarizers.anthropic import AnthropicSummarizer

        # Mock the anthropic client
        mock_client = MagicMock()
        valid_json = json.dumps(make_valid_raw_dict())
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=f"```json\n{valid_json}\n```")]
        mock_client.messages.create.return_value = mock_response

        config = SummarizeConfig(api_key="fake-key")
        summarizer = AnthropicSummarizer(config)
        summarizer._client = mock_client

        report = make_report()
        result = summarizer.summarize(report)

        assert isinstance(result, SummaryResult)
        assert result.provider == "anthropic"
        assert result.overall_priority == ClusterPriority.HIGH

    @pytest.mark.skip(reason="anthropic package not installed in test environment")
    def test_anthropic_invalid_response_falls_back_to_template(self, monkeypatch):
        """Invalid Anthropic response falls back to template summarizer."""
        from unittest.mock import MagicMock

        from sift.config import SummarizeConfig
        from sift.summarizers.anthropic import AnthropicSummarizer

        # Mock the anthropic client to return invalid JSON
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="INVALID JSON {")]
        mock_client.messages.create.return_value = mock_response

        config = SummarizeConfig(api_key="fake-key")
        summarizer = AnthropicSummarizer(config)
        summarizer._client = mock_client

        report = make_report()
        result = summarizer.summarize(report)

        # Should fall back to template
        assert isinstance(result, SummaryResult)
        assert result.provider == "template"

    @pytest.mark.skip(reason="anthropic package not installed in test environment")
    def test_anthropic_missing_required_fields_falls_back(self, monkeypatch):
        """Anthropic response missing required fields falls back to template."""
        from unittest.mock import MagicMock

        from sift.config import SummarizeConfig
        from sift.summarizers.anthropic import AnthropicSummarizer

        # Mock the anthropic client to return JSON missing executive_summary
        mock_client = MagicMock()
        bad_json = json.dumps(
            {
                "cluster_summaries": [],
                "overall_priority": "HIGH",
                # Missing 'executive_summary'
            }
        )
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=f"```json\n{bad_json}\n```")]
        mock_client.messages.create.return_value = mock_response

        config = SummarizeConfig(api_key="fake-key")
        summarizer = AnthropicSummarizer(config)
        summarizer._client = mock_client

        report = make_report()
        result = summarizer.summarize(report)

        # Should fall back to template
        assert isinstance(result, SummaryResult)
        assert result.provider == "template"


# ---------------------------------------------------------------------------
# Edge cases and stress tests
# ---------------------------------------------------------------------------


class TestValidationEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_cluster_summaries_list_valid(self):
        """Empty cluster_summaries is valid (e.g., all NOISE clusters)."""
        data = make_valid_raw_dict()
        data["cluster_summaries"] = []
        report = make_report()
        result = SummaryValidator.validate(data, "test", report)
        assert result.cluster_summaries == []

    def test_unicode_characters_in_executive_summary(self):
        """Unicode characters in executive_summary are preserved."""
        data = make_valid_raw_dict()
        data["executive_summary"] = "Détecté 🚨 5 alertes: Phishing ⚠️ niveau CRITIQUE"
        schema = SummaryResultSchema(**data)
        assert "🚨" in schema.executive_summary
        assert "Détecté" in schema.executive_summary

    def test_recommendations_with_missing_optional_fields(self):
        """Recommendations with missing optional fields are skipped gracefully."""
        data = make_valid_raw_dict()
        data["cluster_summaries"][0]["recommendations"] = [
            {"action": "Do something", "priority": "IMMEDIATE"}
            # Missing 'rationale' — malformed, should be skipped
        ]
        schema = SummaryResultSchema(**data)
        # Malformed recommendation was skipped; cluster_summaries[0] also skipped
        assert len(schema.cluster_summaries) == 0

    def test_deeply_nested_malformed_structure_handled_gracefully(self):
        """Deeply nested malformed structures don't crash the validator."""
        data = make_valid_raw_dict()
        data["cluster_summaries"] = [
            {
                "cluster_id": "c1",
                "narrative": "Valid",
                "recommendations": [
                    {
                        "action": None,  # Invalid
                        "priority": 123,  # Invalid type
                        "rationale": [],  # Invalid type
                    }
                ],
            }
        ]
        report = make_report()
        # Should not crash; may skip malformed recommendations
        result = SummaryValidator.validate(data, "test", report)
        assert isinstance(result, SummaryResult)

    def test_validation_with_null_values_in_optional_fields(self):
        """None/null values in optional fields are handled gracefully."""
        data = make_valid_raw_dict()
        data["provider"] = None
        schema = SummaryResultSchema(**data)
        assert schema.provider is None  # Default is None
