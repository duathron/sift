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
from .prompt import (
    build_cluster_prompt,
    build_cluster_prompt_with_examples,
    get_system_prompt,
)
from .validation import SummaryValidator

if TYPE_CHECKING:
    pass

_DEFAULT_MODEL = "gpt-4o-mini"


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

        Builds a structured prompt from the triage report with few-shot examples,
        sends it to the OpenAI Chat Completions API, and parses the JSON response
        into a :class:`SummaryResult`.

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
        system_prompt = get_system_prompt(self.name)
        prompt = build_cluster_prompt_with_examples(report, self._config, self.name)

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                max_tokens=self._config.max_tokens,
                temperature=self._config.temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
            )
        except self._openai.OpenAIError as exc:
            raise RuntimeError(
                f"OpenAI API error while generating summary: {exc}"
            ) from exc

        response_text = response.choices[0].message.content or ""

        return self._parse_and_validate_response(response_text, report)

    def _parse_and_validate_response(
        self, response_text: str, report: TriageReport
    ) -> SummaryResult:
        """Parse and validate LLM response with fallback to template on failure.

        Args:
            response_text: Raw text response from OpenAI.
            report: The triage report being summarized.

        Returns:
            A validated :class:`SummaryResult`, or a template-generated fallback.
        """
        try:
            # Strip markdown code fences if present: ```json ... ``` or ``` ... ```
            stripped = response_text.strip()
            fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", stripped)
            if fence_match:
                stripped = fence_match.group(1).strip()

            data = json.loads(stripped)

            # Validate the parsed JSON against schema
            return SummaryValidator.validate(data, self.name, report)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            # Graceful degradation: fall back to rule-based template summarizer
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(
                f"Failed to parse/validate OpenAI response: {exc}. "
                f"Falling back to template summarizer."
            )
            from .template import TemplateSummarizer  # noqa: PLC0415

            return TemplateSummarizer().summarize(report)
