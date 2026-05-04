"""Mock LLM provider — deterministic, zero-dependency summarizer for testing.

Produces consistent, predictable output from TriageReport without any API calls
or randomness. Internally uses TemplateSummarizer logic but ensures every
invocation returns identical output given the same input.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sift.models import SummaryResult, TriageReport
from sift.summarizers.template import TemplateSummarizer


class MockSummarizer:
    """Mock LLM summarizer implementing :class:`~sift.summarizers.protocol.SummarizerProtocol`.

    Uses template-based logic internally but guarantees deterministic output:
    no API calls, no randomness, no external dependencies. Ideal for unit tests,
    CI/CD pipelines, and offline environments.
    """

    def __init__(self):
        """Initialize the MockSummarizer with an internal TemplateSummarizer."""
        self._template = TemplateSummarizer()

    @property
    def name(self) -> str:
        """Identifier reported in :attr:`~sift.models.SummaryResult.provider`."""
        return "mock"

    def summarize(self, report: TriageReport) -> SummaryResult:
        """Generate a deterministic :class:`~sift.models.SummaryResult` from *report*.

        The implementation is fully deterministic: given the same input it will
        always produce the same output, with the provider field set to "mock".

        No external API calls are made. No randomness is introduced.

        Args:
            report: A completed :class:`~sift.models.TriageReport` with clusters
                already computed.

        Returns:
            A :class:`~sift.models.SummaryResult` with an executive summary,
            per-cluster narratives, rule-based recommendations, and an
            ``overall_priority`` derived from the highest cluster priority.
            The ``provider`` field is set to "mock".
        """
        # Use the internal template summarizer to produce the core summary
        result = self._template.summarize(report)

        # Override the provider field to "mock" and ensure UTC timestamp
        return result.model_copy(
            update={
                "provider": "mock",
                "generated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
            }
        )
