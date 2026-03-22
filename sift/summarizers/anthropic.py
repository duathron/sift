"""Anthropic (Claude) summarizer for sift.

Requires the ``anthropic`` package, available via::

    pip install sift-triage[llm]
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..config import SummarizeConfig
from ..models import (
    ClusterPriority,
    ClusterSummary,
    Recommendation,
    SummaryResult,
    TriageReport,
)
from .prompt import SYSTEM_PROMPT, build_cluster_prompt

if TYPE_CHECKING:
    pass

_DEFAULT_MODEL = "claude-sonnet-4-20250514"

# Priority string → ClusterPriority fallback map
_PRIORITY_MAP: dict[str, ClusterPriority] = {p.value: p for p in ClusterPriority}


# ---------------------------------------------------------------------------
# Shared JSON parsing helper
# ---------------------------------------------------------------------------

def _parse_summary_json(json_text: str, provider: str, report: TriageReport) -> SummaryResult:
    """Parse LLM JSON output into a :class:`SummaryResult`.

    Handles responses wrapped in markdown fenced code blocks (```json ... ```).
    Falls back to ``MEDIUM`` priority when the returned string is unrecognised.

    Args:
        json_text: Raw text returned by the LLM, possibly with Markdown fencing.
        provider: Short provider identifier (e.g. ``"anthropic"``).
        report: The triage report that was summarised (used for fallback context).

    Returns:
        A fully-populated :class:`SummaryResult`.

    Raises:
        json.JSONDecodeError: If the text cannot be parsed as JSON after stripping
            any Markdown fencing.
    """
    # Strip markdown code fences if present: ```json ... ``` or ``` ... ```
    stripped = json_text.strip()
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", stripped)
    if fence_match:
        stripped = fence_match.group(1).strip()

    data = json.loads(stripped)

    # Build per-cluster summaries
    cluster_summaries: list[ClusterSummary] = []
    for cs in data.get("cluster_summaries", []):
        recommendations: list[Recommendation] = [
            Recommendation(
                action=r.get("action", ""),
                priority=r.get("priority", "MONITOR"),
                rationale=r.get("rationale", ""),
            )
            for r in cs.get("recommendations", [])
        ]
        cluster_summaries.append(
            ClusterSummary(
                cluster_id=cs.get("cluster_id", ""),
                narrative=cs.get("narrative", ""),
                recommendations=recommendations,
            )
        )

    # Map overall_priority string → enum, fall back to MEDIUM
    raw_priority = str(data.get("overall_priority", "")).upper()
    overall_priority = _PRIORITY_MAP.get(raw_priority, ClusterPriority.MEDIUM)

    return SummaryResult(
        executive_summary=data.get("executive_summary", ""),
        cluster_summaries=cluster_summaries,
        overall_priority=overall_priority,
        provider=provider,
        generated_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Summarizer
# ---------------------------------------------------------------------------

class AnthropicSummarizer:
    """Summarizer backed by the Anthropic Messages API (Claude models).

    Args:
        config: ``SummarizeConfig`` containing API key, model name, and generation
            parameters. The API key is resolved in order: ``config.api_key`` →
            ``ANTHROPIC_API_KEY`` environment variable (handled by the SDK).

    Raises:
        ImportError: If the ``anthropic`` package is not installed.
    """

    def __init__(self, config: SummarizeConfig) -> None:
        try:
            import anthropic as _anthropic  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required for the Anthropic summarizer. "
                "Install it with:  pip install sift-triage[llm]"
            ) from exc

        self._anthropic = _anthropic
        self._config = config
        self._model: str = config.model or _DEFAULT_MODEL

        # Build the client; api_key=None lets the SDK fall back to ANTHROPIC_API_KEY.
        self._client = _anthropic.Anthropic(
            api_key=config.api_key or None,
        )

    @property
    def name(self) -> str:
        """Short identifier for this summarizer."""
        return "anthropic"

    def summarize(self, report: TriageReport) -> SummaryResult:
        """Generate a triage summary using Claude.

        Builds a structured prompt from the triage report, sends it to the
        Anthropic Messages API, and parses the JSON response into a
        :class:`SummaryResult`.

        On JSON parse failure, falls back to :class:`~.template.TemplateSummarizer`
        and logs a warning.  On API-level errors the exception is re-raised with
        a human-friendly message prepended.

        Args:
            report: The completed :class:`TriageReport` to summarise.

        Returns:
            A :class:`SummaryResult` populated with the LLM's narrative and
            recommendations, or a template-generated fallback.

        Raises:
            RuntimeError: Wraps any :class:`anthropic.APIError` with a friendly
                message.
        """
        prompt = build_cluster_prompt(report, self._config)

        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=self._config.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
        except self._anthropic.APIError as exc:
            raise RuntimeError(
                f"Anthropic API error while generating summary: {exc}"
            ) from exc

        # Extract text content from the first content block
        response_text = ""
        for block in message.content:
            if hasattr(block, "text"):
                response_text = block.text
                break

        try:
            return _parse_summary_json(response_text, self.name, report)
        except (json.JSONDecodeError, KeyError, TypeError):
            # Graceful degradation: fall back to rule-based template summarizer
            from .template import TemplateSummarizer  # noqa: PLC0415

            return TemplateSummarizer(self._config).summarize(report)
