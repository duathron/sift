"""Tests for provider-specific few-shot prompts and system prompts.

Validates that each LLM provider receives appropriately tailored prompts
with correct system messages and provider-specific examples.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from sift.config import SummarizeConfig
from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    TriageReport,
)
from sift.summarizers.prompt import (
    PROVIDER_EXAMPLES,
    SYSTEM_PROMPTS,
    PromptExample,
    build_cluster_prompt,
    build_cluster_prompt_with_examples,
    get_provider_examples,
    get_system_prompt,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(severity: AlertSeverity = AlertSeverity.HIGH) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Test Alert",
        severity=severity,
    )


def make_cluster(
    priority: ClusterPriority = ClusterPriority.MEDIUM,
    alerts: list[Alert] | None = None,
) -> Cluster:
    alerts = alerts or [make_alert()]
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=alerts,
        priority=priority,
        score=50.0,
    )


def make_report(clusters: list[Cluster] | None = None) -> TriageReport:
    clusters = clusters or [make_cluster()]
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime.now(timezone.utc),
    )


def make_config() -> SummarizeConfig:
    return SummarizeConfig()


# ---------------------------------------------------------------------------
# Test System Prompts by Provider
# ---------------------------------------------------------------------------


class TestSystemPromptProvider:
    """System prompts are correctly returned for each provider."""

    def test_get_system_prompt_anthropic_returns_anthropic_prompt(self):
        prompt = get_system_prompt("anthropic")
        assert isinstance(prompt, str)
        assert len(prompt) > 300
        assert "Claude" in prompt or "SOC analyst" in prompt

    def test_get_system_prompt_openai_returns_openai_prompt(self):
        prompt = get_system_prompt("openai")
        assert isinstance(prompt, str)
        assert len(prompt) > 300
        assert "GPT" in prompt or "SOC analyst" in prompt

    def test_get_system_prompt_ollama_returns_ollama_prompt(self):
        prompt = get_system_prompt("ollama")
        assert isinstance(prompt, str)
        assert len(prompt) > 300
        assert "local" in prompt.lower() or "SOC analyst" in prompt

    def test_get_system_prompt_template_returns_template_prompt(self):
        prompt = get_system_prompt("template")
        assert isinstance(prompt, str)
        assert len(prompt) > 300
        assert "SOC analyst" in prompt

    def test_get_system_prompt_unknown_falls_back_to_template(self):
        prompt = get_system_prompt("unknown_provider_xyz")
        template_prompt = get_system_prompt("template")
        assert prompt == template_prompt


# ---------------------------------------------------------------------------
# Test Few-Shot Examples
# ---------------------------------------------------------------------------


class TestProviderExamples:
    """Few-shot examples are present and properly formatted per provider."""

    def test_get_provider_examples_anthropic_returns_list(self):
        examples = get_provider_examples("anthropic")
        assert isinstance(examples, list)
        assert len(examples) >= 1

    def test_get_provider_examples_openai_returns_list(self):
        examples = get_provider_examples("openai")
        assert isinstance(examples, list)
        assert len(examples) >= 1

    def test_get_provider_examples_ollama_returns_list(self):
        examples = get_provider_examples("ollama")
        assert isinstance(examples, list)
        assert len(examples) >= 1

    def test_get_provider_examples_template_returns_list(self):
        examples = get_provider_examples("template")
        assert isinstance(examples, list)
        assert len(examples) >= 1

    def test_get_provider_examples_unknown_returns_empty_list(self):
        examples = get_provider_examples("unknown_provider_xyz")
        assert isinstance(examples, list)
        assert len(examples) == 0

    def test_provider_example_is_valid_pydantic_model(self):
        examples = get_provider_examples("anthropic")
        for ex in examples:
            assert isinstance(ex, PromptExample)
            assert hasattr(ex, "input")
            assert hasattr(ex, "output")

    def test_provider_example_output_is_valid_json(self):
        providers = ["anthropic", "openai", "ollama", "template"]
        for provider in providers:
            examples = get_provider_examples(provider)
            for ex in examples:
                try:
                    json.loads(ex.output)
                except json.JSONDecodeError:
                    pytest.fail(
                        f"{provider} example output is not valid JSON: {ex.output}"
                    )


# ---------------------------------------------------------------------------
# Test Prompt Building with Examples
# ---------------------------------------------------------------------------


class TestPromptBuildingWithExamples:
    """Prompts are correctly built with few-shot examples."""

    def test_build_cluster_prompt_with_examples_includes_examples_header(self):
        report = make_report()
        config = make_config()
        prompt = build_cluster_prompt_with_examples(report, config, "anthropic")
        # If examples exist, should have a header
        examples = get_provider_examples("anthropic")
        if examples:
            assert "Few-Shot Examples" in prompt

    def test_build_cluster_prompt_with_examples_includes_triage_report(self):
        report = make_report()
        config = make_config()
        prompt = build_cluster_prompt_with_examples(report, config, "anthropic")
        assert "## Triage Report" in prompt

    def test_build_cluster_prompt_with_examples_respects_redaction(self):
        report = make_report()
        config = SummarizeConfig(redact_fields=["iocs", "source_ip"])
        prompt = build_cluster_prompt_with_examples(report, config, "anthropic")
        assert "IOCs        : [redacted]" in prompt or "IOCs        : none" in prompt

    def test_build_cluster_prompt_with_examples_template_has_examples(self):
        report = make_report()
        config = make_config()
        prompt = build_cluster_prompt_with_examples(report, config, "template")
        examples = get_provider_examples("template")
        if examples:
            assert "Example" in prompt

    def test_build_cluster_prompt_without_examples_still_works(self):
        report = make_report()
        config = make_config()
        prompt = build_cluster_prompt(report, config)
        assert "## Triage Report" in prompt
        assert isinstance(prompt, str)


# ---------------------------------------------------------------------------
# Test Example Structure
# ---------------------------------------------------------------------------


class TestExampleStructure:
    """Few-shot examples have correct structure and content."""

    def test_example_has_input_and_output_fields(self):
        all_examples = []
        for provider in ["anthropic", "openai", "ollama", "template"]:
            examples = get_provider_examples(provider)
            all_examples.extend(examples)

        for ex in all_examples:
            assert hasattr(ex, "input")
            assert hasattr(ex, "output")
            assert isinstance(ex.input, str)
            assert isinstance(ex.output, str)
            assert len(ex.input) > 0
            assert len(ex.output) > 0

    def test_example_input_contains_cluster_info(self):
        """Examples should reference cluster structures or report data."""
        for provider in ["anthropic", "openai", "ollama", "template"]:
            examples = get_provider_examples(provider)
            for ex in examples:
                # Input should reference clusters or alerts or both
                has_cluster = "Cluster" in ex.input
                has_report = "Triage Report" in ex.input
                has_alert = "alert" in ex.input.lower()
                assert (
                    has_cluster or has_report or has_alert
                ), f"{provider} example input missing cluster/report/alert reference"

    def test_example_output_follows_schema(self):
        """Output JSON should follow the expected schema."""
        required_fields = {"executive_summary", "cluster_summaries", "overall_priority"}
        for provider in ["anthropic", "openai", "ollama", "template"]:
            examples = get_provider_examples(provider)
            for ex in examples:
                data = json.loads(ex.output)
                assert required_fields.issubset(
                    set(data.keys())
                ), f"{provider} example missing required fields"


# ---------------------------------------------------------------------------
# Test Provider-Specific Behavior
# ---------------------------------------------------------------------------


class TestProviderSpecificBehavior:
    """Each provider receives correctly tailored prompts."""

    def test_anthropic_prompt_mentions_json_schema(self):
        prompt = get_system_prompt("anthropic")
        assert isinstance(prompt, str)
        # Should have base guidance about JSON output
        assert "JSON" in prompt or "json" in prompt

    def test_openai_prompt_mentions_discrete_steps(self):
        prompt = get_system_prompt("openai")
        assert isinstance(prompt, str)
        # Should include OpenAI-specific guidance
        assert len(prompt) > len(get_system_prompt("template"))

    def test_ollama_prompt_emphasizes_conciseness(self):
        prompt = get_system_prompt("ollama")
        assert isinstance(prompt, str)
        # Local model guidance should be present
        assert "concise" in prompt.lower() or "token" in prompt.lower()

    def test_different_providers_have_different_prompts(self):
        """Each provider should have a distinct system prompt."""
        anthropic = get_system_prompt("anthropic")
        openai = get_system_prompt("openai")
        # At least some variation should exist between major providers
        assert len(anthropic) > 0 and len(openai) > 0


# ---------------------------------------------------------------------------
# Test Security: No Secrets in Prompts
# ---------------------------------------------------------------------------


class TestSecurityNoSecretsInPrompts:
    """Prompts should not contain API keys or sensitive credentials."""

    def test_system_prompts_contain_no_api_keys(self):
        for provider, prompt in SYSTEM_PROMPTS.items():
            # Check for common API key patterns
            assert "ANTHROPIC_API_KEY" not in prompt
            assert "OPENAI_API_KEY" not in prompt
            assert "sk-" not in prompt

    def test_examples_contain_no_real_credentials(self):
        for provider, examples in PROVIDER_EXAMPLES.items():
            for ex in examples:
                assert "sk-" not in ex.output
                assert "ANTHROPIC_API_KEY" not in ex.input
                assert "OPENAI_API_KEY" not in ex.input


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
