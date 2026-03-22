"""Anthropic (Claude) summarizer for sift.

Requires the ``anthropic`` package, available via::

    pip install sift-triage[llm]
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from ..config import SummarizeConfig
from ..models import (
    SummaryResult,
    TriageReport,
)
from .prompt import (
    build_cluster_prompt_with_examples,
    get_system_prompt,
)
from .validation import SummaryValidator

if TYPE_CHECKING:
    pass

_DEFAULT_MODEL = "claude-sonnet-4-20250514"


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

        Builds a structured prompt from the triage report with few-shot examples,
        sends it to the Anthropic Messages API, and parses the JSON response into a
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
        system_prompt = get_system_prompt(self.name)
        prompt = build_cluster_prompt_with_examples(report, self._config, self.name)

        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=self._config.max_tokens,
                system=system_prompt,
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

        return self._parse_and_validate_response(response_text, report)

    def _parse_and_validate_response(
        self, response_text: str, report: TriageReport
    ) -> SummaryResult:
        """Parse and validate LLM response with fallback to template on failure.

        Args:
            response_text: Raw text response from Claude.
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
                f"Failed to parse/validate Anthropic response: {exc}. "
                f"Falling back to template summarizer."
            )
            from .template import TemplateSummarizer  # noqa: PLC0415

            return TemplateSummarizer().summarize(report)
