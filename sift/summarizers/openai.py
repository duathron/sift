"""OpenAI summarizer for sift.

Requires the ``openai`` package, available via::

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
            RuntimeError: Wraps any :class:`openai.OpenAIError`, or a
                parse/validation failure, with a friendly message.
        """
        from shipwright_kit.llm import openai_complete  # noqa: PLC0415

        system_prompt = get_system_prompt(self.name)
        prompt = build_cluster_prompt_with_examples(report, self._config, self.name)

        try:
            response_text = openai_complete(
                client=self._client,
                model=self._model,
                max_tokens=self._config.max_tokens,
                system=system_prompt,
                user=prompt,
                temperature=self._config.temperature,
            )
        except self._openai.OpenAIError as exc:
            raise RuntimeError(f"OpenAI API error while generating summary: {exc}") from exc

        return self._parse_and_validate_response(response_text, report)

    def _parse_and_validate_response(self, response_text: str, report: TriageReport) -> SummaryResult:
        """Parse and validate the LLM response.

        F2 cut-1: this used to catch parse/validation failures and silently
        degrade to :class:`~.template.TemplateSummarizer`. It now raises
        :class:`RuntimeError` so the caller can surface a loud, machine-legible
        failure instead of masquerading a template as an LLM analysis.

        Args:
            response_text: Raw text response from OpenAI.
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
            raise RuntimeError(f"Failed to parse/validate OpenAI response: {exc}") from exc
