"""Ollama summarizer for sift.

Uses only Python standard-library HTTP (``urllib.request``) — no third-party
Ollama SDK required.  Requires a running Ollama instance (default:
``http://localhost:11434``).
"""

from __future__ import annotations

# NOTE: `urllib.request` is not called directly in this file anymore (the POST now
# goes through shipwright_kit.llm.ollama_generate), but the import must stay: tests
# patch it via the "sift.summarizers.ollama.urllib.request.urlopen" path, and since
# shipwright_kit.llm imports the same singleton urllib.request module, patching it
# here transparently patches the call ollama_generate() makes too.
import json
import re
import urllib.error
import urllib.request  # noqa: F401

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

        F2 cut-1 (2026-07-03 MeetUp — ``2026-07-03-f2-llm-failure-posture.md``):
        previously *any* error (network, HTTP, JSON parse) was swallowed by a
        bare ``except Exception`` and silently degraded to
        :class:`~.template.TemplateSummarizer` — the analyst would receive a
        template summary believing it was an LLM analysis, with zero logging.
        That silent substitution is now REMOVED: on any failure this method
        raises :class:`RuntimeError` instead. The caller (``sift/main.py``)
        catches it, prints a loud ``LLM SUMMARY UNAVAILABLE`` notice, marks the
        report as degraded (machine-legible marker + reserved exit code 4),
        and still renders the rule-based cluster analysis — nothing is thrown
        away, but nothing masquerades as an LLM summary either.

        Args:
            report: The completed :class:`TriageReport` to summarise.

        Returns:
            A :class:`SummaryResult` populated with the model's narrative and
            recommendations.

        Raises:
            RuntimeError: On any network, HTTP, or response-parsing/validation
                failure.
        """
        try:
            return self._call_ollama(report)
        except RuntimeError:
            # Already a friendly, well-formed error (e.g. from
            # _parse_and_validate_response) — propagate as-is.
            raise
        except Exception as exc:  # noqa: BLE001 — network/HTTP errors from urllib
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

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
        from shipwright_kit.llm import ollama_generate  # noqa: PLC0415

        system_prompt = get_system_prompt(self.name)
        user_prompt = build_cluster_prompt_with_examples(report, self._config, self.name)

        llm_text = ollama_generate(
            base_url=self._base_url,
            model=self._model,
            system=system_prompt,
            user=user_prompt,
            timeout=None,
            system_mode="fold",
        )

        return self._parse_and_validate_response(llm_text, report)

    def _parse_and_validate_response(self, response_text: str, report: TriageReport) -> SummaryResult:
        """Parse and validate the LLM response.

        F2 cut-1: this used to catch parse/validation failures and silently
        degrade to :class:`~.template.TemplateSummarizer` (with only a
        ``logging.warning`` — invisible unless logging was configured). It now
        raises :class:`RuntimeError` so the caller can surface a loud,
        machine-legible failure instead of masquerading a template as an LLM
        analysis.

        Args:
            response_text: Raw text response from Ollama.
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
            raise RuntimeError(f"Failed to parse/validate Ollama response: {exc}") from exc
