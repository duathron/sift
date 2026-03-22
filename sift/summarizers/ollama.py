"""Ollama summarizer for sift.

Uses only Python standard-library HTTP (``urllib.request``) — no third-party
Ollama SDK required.  Requires a running Ollama instance (default:
``http://localhost:11434``).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

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

_DEFAULT_MODEL = "llama3.2"
_DEFAULT_BASE_URL = "http://localhost:11434"


# ---------------------------------------------------------------------------
# Summarizer
# ---------------------------------------------------------------------------

class OllamaSummarizer:
    """Summarizer backed by a local Ollama instance.

    Uses ``urllib.request`` from the Python standard library — no third-party
    HTTP client or Ollama SDK is needed.

    Args:
        config: ``SummarizeConfig`` containing model name and generation parameters.
            ``config.api_key`` is ignored (Ollama has no authentication by default).
        base_url: Base URL of the Ollama HTTP API.  Defaults to
            ``http://localhost:11434``.
    """

    def __init__(
        self,
        config: SummarizeConfig,
        base_url: str = _DEFAULT_BASE_URL,
    ) -> None:
        self._config = config
        self._model: str = config.model or _DEFAULT_MODEL
        self._base_url = base_url.rstrip("/")
        self._generate_url = f"{self._base_url}/api/generate"

    @property
    def name(self) -> str:
        """Short identifier for this summarizer."""
        return "ollama"

    def summarize(self, report: TriageReport) -> SummaryResult:
        """Generate a triage summary using a locally-running Ollama model.

        Constructs a combined system+user prompt (Ollama's ``/api/generate``
        endpoint does not have a dedicated system-message field in all versions,
        so the system prompt is prepended inline), POSTs to the Ollama API, and
        parses the JSON response.

        On *any* error (network, HTTP, JSON parse), falls back to
        :class:`~.template.TemplateSummarizer` to ensure the CLI always produces
        output.

        Args:
            report: The completed :class:`TriageReport` to summarise.

        Returns:
            A :class:`SummaryResult` populated with the model's narrative and
            recommendations, or a template-generated fallback on any failure.
        """
        try:
            return self._call_ollama(report)
        except Exception:  # noqa: BLE001
            from .template import TemplateSummarizer  # noqa: PLC0415

            return TemplateSummarizer(self._config).summarize(report)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_ollama(self, report: TriageReport) -> SummaryResult:
        """POST to the Ollama ``/api/generate`` endpoint and parse the result.

        Args:
            report: Triage report to summarise.

        Returns:
            Parsed :class:`SummaryResult`.

        Raises:
            urllib.error.URLError: On network or HTTP errors.
            json.JSONDecodeError: If the Ollama response body or the embedded
                LLM output cannot be parsed as JSON.
            KeyError: If the Ollama response is missing the ``"response"`` field.
        """
        system_prompt = get_system_prompt(self.name)
        user_prompt = build_cluster_prompt_with_examples(report, self._config, self.name)

        # Prepend system prompt inline — works across all Ollama versions.
        combined_prompt = f"{system_prompt}\n\n{user_prompt}"

        payload = json.dumps(
            {
                "model": self._model,
                "prompt": combined_prompt,
                "stream": False,
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            self._generate_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")

        outer = json.loads(body)
        llm_text: str = outer["response"]

        return self._parse_and_validate_response(llm_text, report)

    def _parse_and_validate_response(
        self, response_text: str, report: TriageReport
    ) -> SummaryResult:
        """Parse and validate LLM response with fallback to template on failure.

        Args:
            response_text: Raw text response from Ollama.
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
                f"Failed to parse/validate Ollama response: {exc}. "
                f"Falling back to template summarizer."
            )
            from .template import TemplateSummarizer  # noqa: PLC0415

            return TemplateSummarizer().summarize(report)
