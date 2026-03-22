"""Validation layer for LLM-generated summaries.

This module provides strict validation of :class:`~sift.models.SummaryResult`
objects returned by LLM summarizers, with automatic fallback to the template
summarizer on validation failure.

The validation ensures that all required fields are populated with sensible
values and that nested structures conform to expected schema. Type coercion
is performed where appropriate (e.g., string → :class:`~sift.models.ClusterPriority`).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator

from sift.models import (
    ClusterPriority,
    ClusterSummary,
    Recommendation,
    SummaryResult,
    TriageReport,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SummaryResultSchema — strict Pydantic validation model
# ---------------------------------------------------------------------------


class SummaryResultSchema(BaseModel):
    """Strict validation schema for LLM-generated summary results.

    This Pydantic v2 model enforces required fields, provides sensible defaults
    for optional fields, and coerces types where possible.

    Fields:
        executive_summary: Non-empty narrative summary of the entire triage run.
        cluster_summaries: At least one cluster summary (can be empty for NOISE-only clusters).
        overall_priority: The highest priority across all clusters; coerced from string.
        recommendations: Optional list of high-level recommendations. Defaults to empty.
        provider: Optional provider identifier (used for logging). Defaults to "unknown".
    """

    executive_summary: str = Field(
        ..., min_length=1, max_length=10000, description="Executive summary (non-empty, max 10K chars)"
    )
    cluster_summaries: list[ClusterSummary] = Field(
        default_factory=list, description="Per-cluster summaries (can be empty)"
    )
    overall_priority: str = Field(
        default="MEDIUM", description="Overall priority (will be coerced to ClusterPriority enum)"
    )
    recommendations: list[Recommendation] = Field(
        default_factory=list, description="Optional top-level recommendations"
    )
    provider: Optional[str] = Field(default=None, description="Provider identifier for logging")
    generated_at: Optional[datetime] = Field(
        default=None, description="Optional timestamp for generated_at field"
    )

    @field_validator("overall_priority", mode="before")
    @classmethod
    def coerce_priority(cls, v: Any) -> str:
        """Coerce overall_priority to uppercase string; validate against allowed values.

        Accepts: str (coerced to uppercase), ClusterPriority enum, or any object
        with a .value attribute.

        Raises:
            ValueError: If the value cannot be coerced to a valid ClusterPriority.
        """
        if isinstance(v, ClusterPriority):
            return v.value

        # Try to extract .value from objects (e.g., Enum-like)
        if hasattr(v, "value"):
            v = v.value

        # Coerce to string and uppercase
        v_str = str(v).upper().strip() if v is not None else ""

        # Validate against allowed priorities
        allowed = {p.value for p in ClusterPriority}
        if v_str not in allowed:
            raise ValueError(
                f"overall_priority '{v_str}' is not a valid ClusterPriority. "
                f"Allowed: {sorted(allowed)}"
            )

        return v_str

    @field_validator("executive_summary", mode="before")
    @classmethod
    def strip_summary(cls, v: Any) -> str:
        """Strip whitespace from executive summary."""
        if isinstance(v, str):
            return v.strip()
        return str(v) if v is not None else ""

    @field_validator("cluster_summaries", mode="before")
    @classmethod
    def ensure_list_cluster_summaries(cls, v: Any) -> list[ClusterSummary]:
        """Ensure cluster_summaries is a list; coerce dicts to ClusterSummary if needed."""
        if not isinstance(v, list):
            return []

        result = []
        for item in v:
            if isinstance(item, ClusterSummary):
                result.append(item)
            elif isinstance(item, dict):
                try:
                    result.append(ClusterSummary(**item))
                except (ValidationError, TypeError):
                    # Skip malformed cluster summary
                    logger.warning(f"Skipped malformed cluster summary: {item}")
        return result

    @field_validator("recommendations", mode="before")
    @classmethod
    def ensure_list_recommendations(cls, v: Any) -> list[Recommendation]:
        """Ensure recommendations is a list; coerce dicts to Recommendation if needed."""
        if not isinstance(v, list):
            return []

        result = []
        for item in v:
            if isinstance(item, Recommendation):
                result.append(item)
            elif isinstance(item, dict):
                try:
                    result.append(Recommendation(**item))
                except (ValidationError, TypeError):
                    # Skip malformed recommendation
                    logger.warning(f"Skipped malformed recommendation: {item}")
        return result

    model_config = {
        "extra": "ignore",  # Ignore unknown fields
    }


# ---------------------------------------------------------------------------
# SummaryValidator — validation logic with fallback
# ---------------------------------------------------------------------------


class SummaryValidator:
    """Validates LLM-generated summaries and provides fallback to template summarizer.

    This class encapsulates the validation logic and is responsible for detecting
    when an LLM response has failed validation, logging appropriate warnings, and
    triggering a fallback to the deterministic template summarizer.
    """

    @staticmethod
    def validate(
        raw_data: dict[str, Any],
        provider: str,
        report: TriageReport,
    ) -> SummaryResult:
        """Validate a raw dictionary as a SummaryResult, with fallback to template.

        Args:
            raw_data: Dictionary parsed from LLM JSON output.
            provider: Short provider identifier (e.g., "anthropic", "openai").
            report: The triage report being summarized (used for fallback context).

        Returns:
            A valid :class:`SummaryResult`. On validation failure, falls back to
            the template summarizer and logs a warning.
        """
        try:
            schema = SummaryResultSchema(**raw_data)
            priority_enum = _string_to_priority(schema.overall_priority)

            return SummaryResult(
                executive_summary=schema.executive_summary,
                cluster_summaries=schema.cluster_summaries,
                overall_priority=priority_enum,
                provider=schema.provider or provider,
                generated_at=schema.generated_at or datetime.now(tz=timezone.utc),
            )
        except (ValidationError, ValueError, KeyError, TypeError) as exc:
            logger.warning(
                f"Validation failed for {provider} summary: {exc}. "
                f"Falling back to template summarizer."
            )
            from .template import TemplateSummarizer  # noqa: PLC0415

            return TemplateSummarizer().summarize(report)

    @staticmethod
    def validate_field(field_name: str, value: Any, field_type: type) -> bool:
        """Quick validation check for a single field.

        Args:
            field_name: Name of the field being validated (for logging).
            value: The value to validate.
            field_type: Expected type.

        Returns:
            True if the field is valid; False otherwise (warning logged).
        """
        if not isinstance(value, field_type):
            logger.warning(
                f"Field '{field_name}' has type {type(value).__name__}, "
                f"expected {field_type.__name__}"
            )
            return False
        return True


def _string_to_priority(priority_str: str) -> ClusterPriority:
    """Convert a priority string to a ClusterPriority enum.

    Args:
        priority_str: Priority as string (e.g., "CRITICAL", "MEDIUM").

    Returns:
        The corresponding :class:`ClusterPriority` enum value.

    Raises:
        ValueError: If the string does not match a valid priority.
    """
    try:
        return ClusterPriority[priority_str.upper()]
    except KeyError:
        logger.warning(
            f"Unknown priority '{priority_str}'; defaulting to MEDIUM"
        )
        return ClusterPriority.MEDIUM
