"""OpenAI summarizer for sift.

Requires the ``openai`` package, available via::

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

_DEFAULT_MODEL = "gpt-4o-mini"

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
        provider: Short provider identifier (e.g. ``"openai"``).
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

class OpenAISummarizer:
    """Summarizer backed by the OpenAI Chat Completions API.

    Args:
        config: ``SummarizeConfig`` containing API key, model name, and generation
            parameters. The API key is resolved in order: ``config.api_key`` →
            ``OPENAI_API_KEY`` environment variable (handled by the SDK).

    Raises:
        ImportError: If the ``openai`` package is not installed.
    """

    def __init__(self, config: SummarizeConfig) -> None:
        try:
            import openai as _openai  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for the OpenAI summarizer. "
                "Install it with:  pip install sift-triage[llm]"
            ) from exc

        self._openai = _openai
        self._config = config
        self._model: str = config.model or _DEFAULT_MODEL

        # Build the client; api_key=None lets the SDK fall back to OPENAI_API_KEY.
        self._client = _openai.OpenAI(
            api_key=config.api_key or None,
        )

    @property
    def name(self) -> str:
        """Short identifier for this summarizer."""
        return "openai"

    def summarize(self, report: TriageReport) -> SummaryResult:
        """Generate a triage summary using an OpenAI chat model.

        Builds a structured prompt from the triage report, sends it to the
        OpenAI Chat Completions API, and parses the JSON response into a
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
            RuntimeError: Wraps any :class:`openai.OpenAIError` with a friendly
                message.
        """
        prompt = build_cluster_prompt(report, self._config)

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                max_tokens=self._config.max_tokens,
                temperature=self._config.temperature,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
        except self._openai.OpenAIError as exc:
            raise RuntimeError(
                f"OpenAI API error while generating summary: {exc}"
            ) from exc

        response_text = response.choices[0].message.content or ""

        try:
            return _parse_summary_json(response_text, self.name, report)
        except (json.JSONDecodeError, KeyError, TypeError):
            # Graceful degradation: fall back to rule-based template summarizer
            from .template import TemplateSummarizer  # noqa: PLC0415

            return TemplateSummarizer(self._config).summarize(report)
