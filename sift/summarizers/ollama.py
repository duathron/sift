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
from datetime import datetime, timezone

from ..config import SummarizeConfig
from ..models import (
    ClusterPriority,
    ClusterSummary,
    Recommendation,
    SummaryResult,
    TriageReport,
)
from .prompt import SYSTEM_PROMPT, build_cluster_prompt

_DEFAULT_MODEL = "llama3.2"
_DEFAULT_BASE_URL = "http://localhost:11434"

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
        provider: Short provider identifier (e.g. ``"ollama"``).
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
        user_prompt = build_cluster_prompt(report, self._config)

        # Prepend system prompt inline — works across all Ollama versions.
        combined_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"

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

        return _parse_summary_json(llm_text, self.name, report)
