"""Characterization tests for sift's LLM-backed summarizer providers.

W3 PREREQUISITE: these tests pin what AnthropicSummarizer, OpenAISummarizer, and
OllamaSummarizer *actually do today* — the request they build, how they parse a
response, and their error/fallback behavior — before the provider logic is
extracted into a shared ``shipwright_kit.llm`` layer. This is characterization,
not specification: where a provider's current behavior looks inconsistent or
odd (e.g. the temperature-passing asymmetry, or Ollama's blanket exception
swallow), the test pins the ODD behavior as-is and calls it out in a comment.
Nothing under ``sift/summarizers/`` is changed by this file.

All external clients are mocked — the ``anthropic`` SDK client, the ``openai``
SDK client, and ``urllib.request.urlopen`` for Ollama. No live network, no real
API keys.
"""

from __future__ import annotations

import json
import urllib.error
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import httpx
import pytest

from sift.config import SummarizeConfig
from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    SummaryResult,
    TriageReport,
)
from sift.summarizers.ollama import OllamaSummarizer

anthropic = pytest.importorskip("anthropic", reason="anthropic extra not installed — see pyproject [llm]")
openai = pytest.importorskip("openai", reason="openai extra not installed — see pyproject [llm]")

from sift.summarizers.anthropic import AnthropicSummarizer  # noqa: E402
from sift.summarizers.openai import OpenAISummarizer  # noqa: E402

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_alert(severity: AlertSeverity = AlertSeverity.HIGH) -> Alert:
    return Alert(id=str(uuid.uuid4()), title="Suspicious Login", severity=severity, source_ip="203.0.113.15")


def make_cluster(priority: ClusterPriority = ClusterPriority.HIGH) -> Cluster:
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=[make_alert()],
        priority=priority,
        score=50.0,
        iocs=["203.0.113.15"],
    )


def make_report(clusters: list[Cluster] | None = None) -> TriageReport:
    clusters = clusters if clusters is not None else [make_cluster()]
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def valid_llm_dict() -> dict:
    """A canned, schema-valid LLM JSON response body."""
    return {
        "executive_summary": "1 HIGH cluster requires review.",
        "cluster_summaries": [
            {
                "cluster_id": "c-1",
                "narrative": "Suspicious login from a foreign IP.",
                "recommendations": [
                    {"action": "Block IP", "priority": "IMMEDIATE", "rationale": "Confirmed hostile source."}
                ],
            }
        ],
        "overall_priority": "HIGH",
    }


def fenced(body: str, lang: str = "json") -> str:
    return f"```{lang}\n{body}\n```"


# ---------------------------------------------------------------------------
# Anthropic — request construction
# ---------------------------------------------------------------------------


class TestAnthropicRequestConstruction:
    """Pins the exact kwargs AnthropicSummarizer sends to messages.create()."""

    def _summarizer_with_mock_client(self, config: SummarizeConfig | None = None):
        config = config or SummarizeConfig(provider="anthropic", api_key="fake-key")
        summarizer = AnthropicSummarizer(config)
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=json.dumps(valid_llm_dict()))]
        mock_client.messages.create.return_value = mock_response
        summarizer._client = mock_client
        return summarizer, mock_client

    def test_sends_model_max_tokens_system_and_user_message(self):
        config = SummarizeConfig(provider="anthropic", api_key="fake-key", model="claude-sonnet-4-6", max_tokens=2048)
        summarizer, mock_client = self._summarizer_with_mock_client(config)
        summarizer.summarize(make_report())

        kwargs = mock_client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-sonnet-4-6"
        assert kwargs["max_tokens"] == 2048
        assert isinstance(kwargs["system"], str) and len(kwargs["system"]) > 0
        assert kwargs["messages"] == [{"role": "user", "content": kwargs["messages"][0]["content"]}]
        assert "## Triage Report" in kwargs["messages"][0]["content"]

    def test_default_model_used_when_config_model_is_none(self):
        config = SummarizeConfig(provider="anthropic", api_key="fake-key")
        summarizer, mock_client = self._summarizer_with_mock_client(config)
        summarizer.summarize(make_report())
        # Pinned current default — CURRENT behavior, not a guarantee W3 must keep.
        assert mock_client.messages.create.call_args.kwargs["model"] == "claude-sonnet-4-6"

    def test_temperature_is_NOT_sent_current_asymmetry(self):
        """ASYMMETRY: Anthropic omits temperature entirely (SDK default applies)."""
        summarizer, mock_client = self._summarizer_with_mock_client()
        summarizer.summarize(make_report())
        assert "temperature" not in mock_client.messages.create.call_args.kwargs

    def test_no_response_format_or_structured_output_param_sent(self):
        summarizer, mock_client = self._summarizer_with_mock_client()
        summarizer.summarize(make_report())
        kwargs = mock_client.messages.create.call_args.kwargs
        assert "response_format" not in kwargs
        assert "tools" not in kwargs

    def test_prompt_wiring_uses_prompt_module(self):
        """The user message is exactly what prompt.build_cluster_prompt_with_examples() builds."""
        from sift.summarizers.prompt import build_cluster_prompt_with_examples

        config = SummarizeConfig(provider="anthropic", api_key="fake-key")
        summarizer, mock_client = self._summarizer_with_mock_client(config)
        report = make_report()
        summarizer.summarize(report)

        expected = build_cluster_prompt_with_examples(report, config, "anthropic")
        assert mock_client.messages.create.call_args.kwargs["messages"][0]["content"] == expected


# ---------------------------------------------------------------------------
# Anthropic — response parsing
# ---------------------------------------------------------------------------


class TestAnthropicResponseParsing:
    def _run_with_content_blocks(self, blocks: list, config: SummarizeConfig | None = None) -> SummaryResult:
        config = config or SummarizeConfig(provider="anthropic", api_key="fake-key")
        summarizer = AnthropicSummarizer(config)
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = blocks
        mock_client.messages.create.return_value = mock_response
        summarizer._client = mock_client
        return summarizer.summarize(make_report())

    def test_parses_plain_json_no_fence(self):
        result = self._run_with_content_blocks([MagicMock(text=json.dumps(valid_llm_dict()))])
        assert result.provider == "anthropic"
        assert result.overall_priority == ClusterPriority.HIGH

    def test_parses_json_fenced_with_json_language_tag(self):
        result = self._run_with_content_blocks([MagicMock(text=fenced(json.dumps(valid_llm_dict()), "json"))])
        assert result.provider == "anthropic"

    def test_parses_json_fenced_without_language_tag(self):
        result = self._run_with_content_blocks([MagicMock(text=fenced(json.dumps(valid_llm_dict()), ""))])
        assert result.provider == "anthropic"

    def test_takes_first_block_with_text_attribute(self):
        """CURRENT behavior: extraction breaks on the FIRST block exposing `.text`,
        even if earlier non-text blocks (e.g. tool_use) precede it."""

        class NoTextBlock:
            type = "tool_use"

        blocks = [NoTextBlock(), MagicMock(text=json.dumps(valid_llm_dict()))]
        result = self._run_with_content_blocks(blocks)
        assert result.provider == "anthropic"

    def test_no_text_bearing_block_yields_empty_string_and_falls_back(self):
        """CURRENT quirk: if no content block exposes `.text`, response_text stays ""
        and json.JSONDecodeError triggers the template fallback (not a crash)."""

        class NoTextBlock:
            type = "tool_use"

        result = self._run_with_content_blocks([NoTextBlock()])
        assert result.provider == "template"

    def test_invalid_json_falls_back_to_template(self):
        result = self._run_with_content_blocks([MagicMock(text="not json at all {")])
        assert result.provider == "template"

    def test_missing_required_field_falls_back_to_template(self):
        bad = valid_llm_dict()
        del bad["executive_summary"]
        result = self._run_with_content_blocks([MagicMock(text=json.dumps(bad))])
        assert result.provider == "template"


# ---------------------------------------------------------------------------
# Anthropic — error handling (NOT a silent fallback; re-raised as RuntimeError)
# ---------------------------------------------------------------------------


class TestAnthropicErrorHandling:
    def test_api_error_is_reraised_as_runtime_error_not_swallowed(self):
        """ASYMMETRY vs Ollama: Anthropic re-raises API-level errors loudly."""
        config = SummarizeConfig(provider="anthropic", api_key="fake-key")
        summarizer = AnthropicSummarizer(config)
        mock_client = MagicMock()
        req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        mock_client.messages.create.side_effect = anthropic.APIError("boom", request=req, body=None)
        summarizer._client = mock_client

        with pytest.raises(RuntimeError, match="Anthropic API error"):
            summarizer.summarize(make_report())


# ---------------------------------------------------------------------------
# OpenAI — request construction (0-test gap being filled)
# ---------------------------------------------------------------------------


class TestOpenAIRequestConstruction:
    def _summarizer_with_mock_client(self, config: SummarizeConfig | None = None):
        config = config or SummarizeConfig(provider="openai", api_key="fake-key")
        summarizer = OpenAISummarizer(config)
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content=json.dumps(valid_llm_dict())))]
        mock_client.chat.completions.create.return_value = mock_response
        summarizer._client = mock_client
        return summarizer, mock_client

    def test_sends_model_max_tokens_temperature_and_two_role_messages(self):
        config = SummarizeConfig(
            provider="openai", api_key="fake-key", model="gpt-4o", max_tokens=1024, temperature=0.3
        )
        summarizer, mock_client = self._summarizer_with_mock_client(config)
        summarizer.summarize(make_report())

        kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "gpt-4o"
        assert kwargs["max_tokens"] == 1024
        assert kwargs["temperature"] == 0.3
        messages = kwargs["messages"]
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert "## Triage Report" in messages[1]["content"]

    def test_default_model_used_when_config_model_is_none(self):
        summarizer, mock_client = self._summarizer_with_mock_client()
        summarizer.summarize(make_report())
        assert mock_client.chat.completions.create.call_args.kwargs["model"] == "gpt-4o-mini"

    def test_temperature_IS_sent_from_config_current_asymmetry(self):
        """ASYMMETRY: OpenAI is the ONLY provider that forwards config.temperature."""
        config = SummarizeConfig(provider="openai", api_key="fake-key", temperature=0.77)
        summarizer, mock_client = self._summarizer_with_mock_client(config)
        summarizer.summarize(make_report())
        assert mock_client.chat.completions.create.call_args.kwargs["temperature"] == 0.77

    def test_default_temperature_is_config_default_point_one(self):
        summarizer, mock_client = self._summarizer_with_mock_client()
        summarizer.summarize(make_report())
        assert mock_client.chat.completions.create.call_args.kwargs["temperature"] == 0.1

    def test_no_response_format_or_structured_output_param_sent(self):
        """CURRENT quirk: JSON compliance relies entirely on the system prompt +
        regex fence-stripping — no `response_format={"type": "json_object"}` and
        no function/tool-calling structured output is used."""
        summarizer, mock_client = self._summarizer_with_mock_client()
        summarizer.summarize(make_report())
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert "response_format" not in kwargs
        assert "tools" not in kwargs
        assert "functions" not in kwargs

    def test_prompt_wiring_uses_prompt_module(self):
        from sift.summarizers.prompt import build_cluster_prompt_with_examples, get_system_prompt

        config = SummarizeConfig(provider="openai", api_key="fake-key")
        summarizer, mock_client = self._summarizer_with_mock_client(config)
        report = make_report()
        summarizer.summarize(report)

        kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert kwargs["messages"][0]["content"] == get_system_prompt("openai")
        assert kwargs["messages"][1]["content"] == build_cluster_prompt_with_examples(report, config, "openai")


# ---------------------------------------------------------------------------
# OpenAI — response parsing
# ---------------------------------------------------------------------------


class TestOpenAIResponseParsing:
    def _run_with_content(self, content, config: SummarizeConfig | None = None) -> SummaryResult:
        config = config or SummarizeConfig(provider="openai", api_key="fake-key")
        summarizer = OpenAISummarizer(config)
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content=content))]
        mock_client.chat.completions.create.return_value = mock_response
        summarizer._client = mock_client
        return summarizer.summarize(make_report())

    def test_parses_plain_json_no_fence(self):
        result = self._run_with_content(json.dumps(valid_llm_dict()))
        assert result.provider == "openai"
        assert result.overall_priority == ClusterPriority.HIGH

    def test_parses_json_fenced_with_json_language_tag(self):
        result = self._run_with_content(fenced(json.dumps(valid_llm_dict()), "json"))
        assert result.provider == "openai"

    def test_parses_json_fenced_without_language_tag(self):
        result = self._run_with_content(fenced(json.dumps(valid_llm_dict()), ""))
        assert result.provider == "openai"

    def test_none_content_falls_back_to_template(self):
        """CURRENT quirk: `response.choices[0].message.content or ""` — a None content
        (e.g. the model returned only a tool call) degrades to "" and fails JSON parse
        rather than raising, so it's caught by the same fallback path."""
        result = self._run_with_content(None)
        assert result.provider == "template"

    def test_invalid_json_falls_back_to_template(self):
        result = self._run_with_content("not json {")
        assert result.provider == "template"

    def test_missing_required_field_falls_back_to_template(self):
        bad = valid_llm_dict()
        del bad["executive_summary"]
        result = self._run_with_content(json.dumps(bad))
        assert result.provider == "template"


# ---------------------------------------------------------------------------
# OpenAI — error handling (NOT a silent fallback; re-raised as RuntimeError)
# ---------------------------------------------------------------------------


class TestOpenAIErrorHandling:
    def test_api_error_is_reraised_as_runtime_error_not_swallowed(self):
        """Same pattern as Anthropic: API-level errors are re-raised, not swallowed."""
        config = SummarizeConfig(provider="openai", api_key="fake-key")
        summarizer = OpenAISummarizer(config)
        mock_client = MagicMock()
        req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
        mock_client.chat.completions.create.side_effect = openai.APIError("boom", request=req, body=None)
        summarizer._client = mock_client

        with pytest.raises(RuntimeError, match="OpenAI API error"):
            summarizer.summarize(make_report())


# ---------------------------------------------------------------------------
# Ollama — request construction (no third-party SDK; urllib.request is mocked)
# ---------------------------------------------------------------------------


class _FakeHTTPResponse:
    """Minimal stand-in for the context-manager object urlopen() returns."""

    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self) -> bytes:
        return self._body


def _install_fake_urlopen(monkeypatch, response_body: dict | None = None, error: Exception | None = None):
    """Patch urllib.request.urlopen inside sift.summarizers.ollama and capture the Request."""
    captured: dict = {}

    def fake_urlopen(req, *args, **kwargs):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["payload"] = json.loads(req.data.decode("utf-8"))
        if error is not None:
            raise error
        return _FakeHTTPResponse(json.dumps(response_body).encode("utf-8"))

    monkeypatch.setattr("sift.summarizers.ollama.urllib.request.urlopen", fake_urlopen)
    return captured


class TestOllamaRequestConstruction:
    def test_posts_to_default_base_url_generate_endpoint(self, monkeypatch):
        captured = _install_fake_urlopen(monkeypatch, {"response": json.dumps(valid_llm_dict())})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        summarizer.summarize(make_report())

        assert captured["url"] == "http://localhost:11434/api/generate"
        assert captured["method"] == "POST"

    def test_custom_base_url_and_trailing_slash_stripped(self, monkeypatch):
        captured = _install_fake_urlopen(monkeypatch, {"response": json.dumps(valid_llm_dict())})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"), base_url="http://gpu-box:11434/")
        summarizer.summarize(make_report())
        assert captured["url"] == "http://gpu-box:11434/api/generate"

    def test_payload_has_model_prompt_stream_false_only(self, monkeypatch):
        captured = _install_fake_urlopen(monkeypatch, {"response": json.dumps(valid_llm_dict())})
        config = SummarizeConfig(provider="ollama", model="llama3.2:70b")
        summarizer = OllamaSummarizer(config)
        summarizer.summarize(make_report())

        payload = captured["payload"]
        assert payload["model"] == "llama3.2:70b"
        assert payload["stream"] is False
        # CURRENT behavior: exactly these 3 keys — no "system", no "options", no temperature.
        assert set(payload.keys()) == {"model", "prompt", "stream"}

    def test_default_model_used_when_config_model_is_none(self, monkeypatch):
        captured = _install_fake_urlopen(monkeypatch, {"response": json.dumps(valid_llm_dict())})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        summarizer.summarize(make_report())
        assert captured["payload"]["model"] == "llama3.2"

    def test_system_prompt_is_prepended_inline_not_a_separate_field(self, monkeypatch):
        """CURRENT behavior: Ollama's /api/generate has no dedicated system-message
        field in all versions, so sift prepends system + '\\n\\n' + user prompt into
        a single combined 'prompt' string."""
        from sift.summarizers.prompt import build_cluster_prompt_with_examples, get_system_prompt

        captured = _install_fake_urlopen(monkeypatch, {"response": json.dumps(valid_llm_dict())})
        config = SummarizeConfig(provider="ollama")
        report = make_report()
        summarizer = OllamaSummarizer(config)
        summarizer.summarize(report)

        expected_system = get_system_prompt("ollama")
        expected_user = build_cluster_prompt_with_examples(report, config, "ollama")
        assert captured["payload"]["prompt"] == f"{expected_system}\n\n{expected_user}"

    def test_content_type_header_is_json(self, monkeypatch):
        captured = _install_fake_urlopen(monkeypatch, {"response": json.dumps(valid_llm_dict())})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        summarizer.summarize(make_report())
        # urllib title-cases header keys it was given.
        assert captured["headers"].get("Content-type") == "application/json"


# ---------------------------------------------------------------------------
# Ollama — response parsing
# ---------------------------------------------------------------------------


class TestOllamaResponseParsing:
    def test_parses_plain_json_no_fence(self, monkeypatch):
        _install_fake_urlopen(monkeypatch, {"response": json.dumps(valid_llm_dict())})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        result = summarizer.summarize(make_report())
        assert result.provider == "ollama"
        assert result.overall_priority == ClusterPriority.HIGH

    def test_parses_json_fenced_with_json_language_tag(self, monkeypatch):
        _install_fake_urlopen(monkeypatch, {"response": fenced(json.dumps(valid_llm_dict()), "json")})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        result = summarizer.summarize(make_report())
        assert result.provider == "ollama"

    def test_outer_response_missing_response_key_falls_back_silently(self, monkeypatch):
        """CURRENT quirk: a KeyError on outer['response'] is caught by the summarize()
        blanket `except Exception` and silently falls back — same as a network error."""
        _install_fake_urlopen(monkeypatch, {"unexpected_key": "oops"})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        result = summarizer.summarize(make_report())
        assert result.provider == "template"

    def test_invalid_inner_json_falls_back_to_template(self, monkeypatch):
        _install_fake_urlopen(monkeypatch, {"response": "not json {"})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        result = summarizer.summarize(make_report())
        assert result.provider == "template"

    def test_missing_required_field_falls_back_to_template(self, monkeypatch):
        bad = valid_llm_dict()
        del bad["executive_summary"]
        _install_fake_urlopen(monkeypatch, {"response": json.dumps(bad)})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        result = summarizer.summarize(make_report())
        assert result.provider == "template"


# ---------------------------------------------------------------------------
# Ollama — error handling: THE asymmetry vs Anthropic/OpenAI.
# ---------------------------------------------------------------------------


class TestOllamaErrorHandling:
    """ASYMMETRY (real quirk, reported not fixed): unlike Anthropic/OpenAI, which
    only fall back to the template on a JSON-parse/validation failure and RE-RAISE
    on API-level errors, Ollama's `summarize()` wraps the entire call in a bare
    `except Exception` and ALWAYS falls back silently — including on network
    failures (server down / unreachable), HTTP errors, and malformed bodies. A
    misconfigured or offline Ollama server therefore produces no visible error to
    the caller, whereas the same misconfiguration on Anthropic/OpenAI raises a
    RuntimeError. W3's shared layer needs to decide whether this divergence is
    intentional (Ollama = "best effort local" vs cloud providers = "must succeed
    or fail loudly") or should be unified.
    """

    def test_network_error_falls_back_to_template_silently_no_raise(self, monkeypatch):
        _install_fake_urlopen(monkeypatch, error=urllib.error.URLError("connection refused"))
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        result = summarizer.summarize(make_report())  # must NOT raise
        assert result.provider == "template"

    def test_http_error_falls_back_to_template_silently_no_raise(self, monkeypatch):
        http_err = urllib.error.HTTPError(
            url="http://localhost:11434/api/generate", code=500, msg="Internal Server Error", hdrs=None, fp=None
        )
        _install_fake_urlopen(monkeypatch, error=http_err)
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        result = summarizer.summarize(make_report())
        assert result.provider == "template"


# ---------------------------------------------------------------------------
# Cross-provider temperature asymmetry — the exact table W3 must decide on.
# ---------------------------------------------------------------------------


class TestCrossProviderTemperatureAsymmetry:
    """Consolidated pin of the temperature-passing asymmetry across all 4 providers.

    | provider  | temperature sent? | value                                    |
    |-----------|--------------------|-------------------------------------------|
    | anthropic | NO                 | omitted; Anthropic SDK/API default applies |
    | openai    | YES                | `config.temperature` (default 0.1)         |
    | ollama    | NO                 | omitted; no "options" dict sent at all     |
    | template  | N/A                | no LLM call — fully deterministic          |
    """

    def test_anthropic_omits_temperature(self):
        config = SummarizeConfig(provider="anthropic", api_key="fake-key", temperature=0.9)
        summarizer = AnthropicSummarizer(config)
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=json.dumps(valid_llm_dict()))]
        mock_client.messages.create.return_value = mock_response
        summarizer._client = mock_client
        summarizer.summarize(make_report())
        assert "temperature" not in mock_client.messages.create.call_args.kwargs

    def test_openai_sends_temperature(self):
        config = SummarizeConfig(provider="openai", api_key="fake-key", temperature=0.9)
        summarizer = OpenAISummarizer(config)
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content=json.dumps(valid_llm_dict())))]
        mock_client.chat.completions.create.return_value = mock_response
        summarizer._client = mock_client
        summarizer.summarize(make_report())
        assert mock_client.chat.completions.create.call_args.kwargs["temperature"] == 0.9

    def test_ollama_omits_temperature(self, monkeypatch):
        captured = _install_fake_urlopen(monkeypatch, {"response": json.dumps(valid_llm_dict())})
        config = SummarizeConfig(provider="ollama", temperature=0.9)
        summarizer = OllamaSummarizer(config)
        summarizer.summarize(make_report())
        assert "temperature" not in captured["payload"]
        assert "options" not in captured["payload"]
