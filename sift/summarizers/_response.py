"""Shared LLM-response parsing/validation for sift summarizers.

The three provider summarizers (:mod:`~sift.summarizers.anthropic`,
:mod:`~sift.summarizers.openai`, :mod:`~sift.summarizers.ollama`) each extract
raw text from their SDK's response in a provider-specific way (Anthropic's
first text block, OpenAI's ``choices[0]``, Ollama's ``response`` key). Once the
raw text is in hand, however, the *parse → validate → raise* tail is identical
across all three. This module houses that shared tail so it lives in one place.

F2 cut-1 (2026-07-03 MeetUp — ``2026-07-03-f2-llm-failure-posture.md``): a JSON
parse/validation failure used to silently fall back to
:class:`~sift.summarizers.template.TemplateSummarizer`. That silent
substitution is REMOVED — a parse/validation failure raises
:class:`RuntimeError` so the caller (``sift/main.py``) can surface a loud,
machine-legible failure instead of masquerading a template as an LLM analysis.

Import-light by design: this module operates on already-extracted text strings
and never imports a provider SDK.
"""

from __future__ import annotations

import json
import re

from ..models import (
    SummaryResult,
    TriageReport,
)
from .validation import SummaryValidator


def parse_and_validate_response(
    response_text: str,
    provider: str,
    provider_label: str,
    report: TriageReport,
) -> SummaryResult:
    """Parse and validate an LLM response into a :class:`SummaryResult`.

    Strips a markdown code fence if present (```json ... ``` or ``` ... ```),
    parses the remainder as JSON, and validates it against the summary schema
    via :meth:`SummaryValidator.validate`.

    F2 cut-1: parse/validation failures raise :class:`RuntimeError` (no silent
    template fallback) so the caller can surface a loud, machine-legible
    failure.

    Args:
        response_text: Raw text response already extracted from the provider's
            SDK payload (provider-specific extraction happens upstream).
        provider: Short provider identifier (e.g. ``"anthropic"``) — passed to
            :meth:`SummaryValidator.validate` and stamped onto the result.
        provider_label: Human-facing provider name for the error message
            (e.g. ``"Anthropic"``).
        report: The triage report being summarized (forwarded unchanged to
            :meth:`SummaryValidator.validate` for call-site compatibility).

    Returns:
        A validated :class:`SummaryResult`.

    Raises:
        RuntimeError: If the response cannot be parsed as JSON or fails schema
            validation.
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
        return SummaryValidator.validate(data, provider, report)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"Failed to parse/validate {provider_label} response: {exc}") from exc
