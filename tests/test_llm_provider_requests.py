"""Characterization tests for sift's LLM-backed summarizer providers.

W3 PREREQUISITE: these tests pin what AnthropicSummarizer, OpenAISummarizer, and
OllamaSummarizer *actually do today* — the request they build, how they parse a
response, and their error/fallback behavior — before the provider logic is
extracted into a shared ``shipwright_kit.llm`` layer. This is characterization,
not specification: where a provider's current behavior looks inconsistent or
odd (e.g. the temperature-passing asymmetry), the test pins the ODD behavior
as-is and calls it out in a comment.

F2 cut-1 (2026-07-03 MeetUp — ``2026-07-03-f2-llm-failure-posture.md``, signed
off): the "silently fall back to TemplateSummarizer on ANY failure" posture
this file used to pin (Ollama's blanket exception swallow, and all three
providers' malformed/invalid-JSON degrade) is a BUG, not a spec — the analyst
receives a template summary while believing it is an LLM analysis. This is a
deliberate, signed-off BEHAVIOR CHANGE: every test below that used to assert
``result.provider == "template"`` on an LLM-side failure now asserts
``pytest.raises(RuntimeError)`` instead (no template substitution — the
caller in ``sift/main.py`` is responsible for the loud notice + degraded exit
code). Each flipped test carries a docstring noting the OLD assertion, the
NEW assertion, and why.

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

    def test_no_text_bearing_block_yields_empty_string_and_raises(self):
        """F2 cut-1 flip. OLD: if no content block exposes `.text`, response_text
        stayed "" and json.JSONDecodeError triggered a silent template fallback
        (`result.provider == "template"`) — not a crash, but a masquerade. NEW:
        the same JSONDecodeError now propagates as RuntimeError — no template
        substitution. Signed off: 2026-07-03 MeetUp F2 cut-1."""

        class NoTextBlock:
            type = "tool_use"

        with pytest.raises(RuntimeError, match="Failed to parse/validate Anthropic response"):
            self._run_with_content_blocks([NoTextBlock()])

    def test_invalid_json_raises_not_falls_back(self):
        """F2 cut-1 flip. OLD: `result.provider == "template"`. NEW: malformed
        JSON from the LLM raises RuntimeError instead of silently degrading to
        a template summary. Signed off: 2026-07-03 MeetUp F2 cut-1."""
        with pytest.raises(RuntimeError, match="Failed to parse/validate Anthropic response"):
            self._run_with_content_blocks([MagicMock(text="not json at all {")])

    def test_missing_required_field_raises_not_falls_back(self):
        """F2 cut-1 flip. OLD: `result.provider == "template"`. NEW: a
        schema-validation failure (missing `executive_summary`) raises
        RuntimeError from SummaryValidator.validate() instead of silently
        falling back to a template. Signed off: 2026-07-03 MeetUp F2 cut-1."""
        bad = valid_llm_dict()
        del bad["executive_summary"]
        with pytest.raises(RuntimeError, match="Validation failed for anthropic summary"):
            self._run_with_content_blocks([MagicMock(text=json.dumps(bad))])


# ---------------------------------------------------------------------------
# Anthropic — error handling (NOT a silent fallback; re-raised as RuntimeError)
# ---------------------------------------------------------------------------


class TestAnthropicErrorHandling:
    """F2 cut-1: UNCHANGED by this behavior change — confirmed still holds.
    Anthropic already re-raised API-level errors as RuntimeError before F2;
    that is now the UNIFIED posture across all three providers (see
    TestOllamaErrorHandling), so this test needed no flip."""

    def test_api_error_is_reraised_as_runtime_error_not_swallowed(self):
        """No longer an asymmetry vs Ollama post-F2 — this is now the shared
        posture: Anthropic re-raises API-level errors loudly, and Ollama does
        too (see TestOllamaErrorHandling)."""
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

    def test_none_content_raises_not_falls_back(self):
        """F2 cut-1 flip. `response.choices[0].message.content or ""` — a None
        content (e.g. the model returned only a tool call) still degrades to ""
        and fails JSON parse (that quirk is unchanged), but OLD: the failure was
        caught and silently returned `result.provider == "template"`. NEW: it
        raises RuntimeError — no template substitution. Signed off: 2026-07-03
        MeetUp F2 cut-1."""
        with pytest.raises(RuntimeError, match="Failed to parse/validate OpenAI response"):
            self._run_with_content(None)

    def test_invalid_json_raises_not_falls_back(self):
        """F2 cut-1 flip. OLD: `result.provider == "template"`. NEW: malformed
        JSON from the LLM raises RuntimeError instead of silently degrading to
        a template summary. Signed off: 2026-07-03 MeetUp F2 cut-1."""
        with pytest.raises(RuntimeError, match="Failed to parse/validate OpenAI response"):
            self._run_with_content("not json {")

    def test_missing_required_field_raises_not_falls_back(self):
        """F2 cut-1 flip. OLD: `result.provider == "template"`. NEW: a
        schema-validation failure (missing `executive_summary`) raises
        RuntimeError from SummaryValidator.validate() instead of silently
        falling back to a template. Signed off: 2026-07-03 MeetUp F2 cut-1."""
        bad = valid_llm_dict()
        del bad["executive_summary"]
        with pytest.raises(RuntimeError, match="Validation failed for openai summary"):
            self._run_with_content(json.dumps(bad))


# ---------------------------------------------------------------------------
# OpenAI — error handling (NOT a silent fallback; re-raised as RuntimeError)
# ---------------------------------------------------------------------------


class TestOpenAIErrorHandling:
    """F2 cut-1: UNCHANGED by this behavior change — confirmed still holds.
    OpenAI already re-raised API-level errors as RuntimeError before F2; that
    is now the UNIFIED posture across all three providers (see
    TestOllamaErrorHandling), so this test needed no flip."""

    def test_api_error_is_reraised_as_runtime_error_not_swallowed(self):
        """Same pattern as Anthropic: API-level errors are re-raised, not
        swallowed. Post-F2 this is the shared posture across all providers."""
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

    def test_outer_response_missing_response_key_raises_not_falls_back(self, monkeypatch):
        """F2 cut-1 flip. OLD: a KeyError on outer['response'] was caught by
        summarize()'s blanket `except Exception` and silently fell back to a
        template (same as a network error) — `result.provider == "template"`.
        NEW: `summarize()` no longer has a bare except-to-template; the KeyError
        is wrapped as RuntimeError and propagates. Signed off: 2026-07-03 MeetUp
        F2 cut-1."""
        _install_fake_urlopen(monkeypatch, {"unexpected_key": "oops"})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        with pytest.raises(RuntimeError, match="Ollama request failed"):
            summarizer.summarize(make_report())

    def test_invalid_inner_json_raises_not_falls_back(self, monkeypatch):
        """F2 cut-1 flip. OLD: `result.provider == "template"`. NEW: malformed
        JSON in the Ollama `response` field raises RuntimeError instead of
        silently degrading to a template summary. Signed off: 2026-07-03 MeetUp
        F2 cut-1."""
        _install_fake_urlopen(monkeypatch, {"response": "not json {"})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        with pytest.raises(RuntimeError, match="Failed to parse/validate Ollama response"):
            summarizer.summarize(make_report())

    def test_missing_required_field_raises_not_falls_back(self, monkeypatch):
        """F2 cut-1 flip. OLD: `result.provider == "template"`. NEW: a
        schema-validation failure (missing `executive_summary`) raises
        RuntimeError from SummaryValidator.validate() instead of silently
        falling back to a template. Signed off: 2026-07-03 MeetUp F2 cut-1."""
        bad = valid_llm_dict()
        del bad["executive_summary"]
        _install_fake_urlopen(monkeypatch, {"response": json.dumps(bad)})
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        with pytest.raises(RuntimeError, match="Validation failed for ollama summary"):
            summarizer.summarize(make_report())


# ---------------------------------------------------------------------------
# Ollama — error handling: THE asymmetry vs Anthropic/OpenAI.
# ---------------------------------------------------------------------------


class TestOllamaErrorHandling:
    """F2 cut-1 (2026-07-03 MeetUp — ``2026-07-03-f2-llm-failure-posture.md``,
    signed off): this class used to pin an ASYMMETRY where, unlike
    Anthropic/OpenAI (which RE-RAISE on API-level errors), Ollama's
    `summarize()` wrapped the entire call in a bare `except Exception` and
    ALWAYS fell back silently — including on network failures (server down /
    unreachable) and HTTP errors — with ZERO logging. A misconfigured or
    offline Ollama server therefore produced no visible error to the caller,
    silently handing the analyst a template summary while they believed it
    was an LLM analysis. That was the real bug behind the F2 MeetUp (a live
    smoke test: `sift triage --provider ollama` with a missing model → 404 →
    silent template fallback).

    UNIFIED POSTURE (this class now pins): Ollama's bare-except-to-template is
    REMOVED. Network/HTTP errors — and, symmetrically, Anthropic/OpenAI's own
    malformed-JSON degrade (see `TestOllamaResponseParsing` et al.) — all now
    raise RuntimeError, exactly like an Anthropic/OpenAI API-level error
    always did. The three providers are no longer asymmetric: NO provider ever
    silently substitutes a template for a failed LLM call. The caller
    (`sift/main.py`) converts the RuntimeError into a loud stderr notice + a
    machine-legible degraded marker + the reserved exit code (4) — the
    rule-based cluster analysis itself is still rendered, never discarded.
    """

    def test_network_error_raises_not_silently_falls_back(self, monkeypatch):
        """F2 cut-1 flip. OLD assertion: `summarizer.summarize(report)` must NOT
        raise and returns `result.provider == "template"`. NEW assertion: it
        DOES raise RuntimeError — the network failure is never masked. Signed
        off: 2026-07-03 MeetUp F2 cut-1 (this was the exact bug the MeetUp was
        triggered by)."""
        _install_fake_urlopen(monkeypatch, error=urllib.error.URLError("connection refused"))
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        with pytest.raises(RuntimeError, match="Ollama request failed"):
            summarizer.summarize(make_report())

    def test_http_error_raises_not_silently_falls_back(self, monkeypatch):
        """F2 cut-1 flip. OLD assertion: `summarizer.summarize(report)` must NOT
        raise and returns `result.provider == "template"`. NEW assertion: it
        DOES raise RuntimeError — an HTTP-level failure (e.g. 404 model not
        found, 500 server error) is never masked. Signed off: 2026-07-03 MeetUp
        F2 cut-1."""
        http_err = urllib.error.HTTPError(
            url="http://localhost:11434/api/generate", code=500, msg="Internal Server Error", hdrs=None, fp=None
        )
        _install_fake_urlopen(monkeypatch, error=http_err)
        summarizer = OllamaSummarizer(SummarizeConfig(provider="ollama"))
        with pytest.raises(RuntimeError, match="Ollama request failed"):
            summarizer.summarize(make_report())


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
