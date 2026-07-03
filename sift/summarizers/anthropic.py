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

_DEFAULT_MODEL = "claude-sonnet-4-6"


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

        F2 cut-1 (2026-07-03 MeetUp — ``2026-07-03-f2-llm-failure-posture.md``):
        a JSON parse/validation failure used to silently fall back to
        :class:`~.template.TemplateSummarizer` (with only a ``logging.warning``).
        That silent substitution is now REMOVED: both API-level errors and
        parse/validation failures raise :class:`RuntimeError`. The caller
        (``sift/main.py``) catches it, prints a loud ``LLM SUMMARY UNAVAILABLE``
        notice, and marks the report degraded (exit code 4) — the rule-based
        cluster analysis still renders.

        Args:
            report: The completed :class:`TriageReport` to summarise.

        Returns:
            A :class:`SummaryResult` populated with the LLM's narrative and
            recommendations.

        Raises:
            RuntimeError: Wraps any :class:`anthropic.APIError`, or a
                parse/validation failure, with a friendly message.
        """
        from shipwright_kit.llm import anthropic_complete  # noqa: PLC0415

        system_prompt = get_system_prompt(self.name)
        prompt = build_cluster_prompt_with_examples(report, self._config, self.name)

        try:
            response_text = anthropic_complete(
                client=self._client,
                model=self._model,
                max_tokens=self._config.max_tokens,
                system=system_prompt,
                user=prompt,
                extract="first_text_block",
            )
        except self._anthropic.APIError as exc:
            raise RuntimeError(f"Anthropic API error while generating summary: {exc}") from exc

        return self._parse_and_validate_response(response_text, report)

    def _parse_and_validate_response(self, response_text: str, report: TriageReport) -> SummaryResult:
        """Parse and validate the LLM response.

        F2 cut-1: this used to catch parse/validation failures and silently
        degrade to :class:`~.template.TemplateSummarizer`. It now raises
        :class:`RuntimeError` so the caller can surface a loud, machine-legible
        failure instead of masquerading a template as an LLM analysis.

        Args:
            response_text: Raw text response from Claude.
            report: The triage report being summarized.

        Returns:
            A validated :class:`SummaryResult`.

        Raises:
            RuntimeError: If the response cannot be parsed as JSON or fails
                schema validation.
        """
        # Strip markdown code fences if present: ```json ... ``` or ``` ... ```
        stripped = response_text.strip()
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", stripped)
        if fence_match:
            stripped = fence_match.group(1).strip()

        try:
            data = json.loads(stripped)
            # Validate the parsed JSON against schema (raises RuntimeError on
            # failure — see SummaryValidator.validate).
            return SummaryValidator.validate(data, self.name, report)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse/validate Anthropic response: {exc}") from exc
