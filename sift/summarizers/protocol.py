"""SummarizerProtocol — structural interface for all summarizer implementations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sift.models import SummaryResult, TriageReport


@runtime_checkable
class SummarizerProtocol(Protocol):
    """Structural interface that every summarizer must satisfy.

    Implementations are free to use any backend (template logic, Anthropic,
    OpenAI, Ollama, etc.) as long as they expose the two members below.
    """

    @property
    def name(self) -> str:
        """Short identifier for this summarizer, e.g. "template" or "anthropic"."""
        ...

    def summarize(self, report: TriageReport) -> SummaryResult:
        """Produce a :class:`SummaryResult` from a completed :class:`TriageReport`.

        Args:
            report: The fully-populated triage report (clusters already computed).

        Returns:
            A ``SummaryResult`` containing the executive summary, per-cluster
            narratives, recommendations, and overall priority.
        """
        ...
