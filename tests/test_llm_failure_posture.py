"""CLI-level coverage for the F2 cut-1 unified LLM-provider-failure posture.

Reference: ``2026-07-03-f2-llm-failure-posture.md`` (MeetUp decision, signed
off). sift is the REFERENCE implementation of this posture for barb/vex to
copy.

The bug this closes: on an LLM-provider failure, sift used to SILENTLY
substitute a rule-based :class:`~sift.summarizers.template.TemplateSummarizer`
result for the requested LLM summary — the analyst (or a downstream pipeline)
received a template while believing it was an LLM analysis, with the CLI
still exiting 0/1 as if nothing had gone wrong.

This module proves the new posture end-to-end via the CLI:
  (a) no TemplateSummarizer output is substituted for a failed LLM
  (b) a loud "LLM SUMMARY UNAVAILABLE" notice appears in the rich AND
      markdown renderers (not just html)
  (c) the run exits with the reserved degraded exit code (4)
  (d) all warnings go to stderr only — a ``--format json`` run's STDOUT stays
      ``json.loads``-parseable, with ``summary: null`` +
      ``summary_error``/``summary_provider`` siblings
  (e) a DELIBERATE ``--provider template`` run (no LLM requested) is never
      flagged degraded — exit 0, no warning, no "unavailable" notice.

The LLM provider under test is Ollama (patched at the ``urllib.request``
seam, same technique as ``tests/test_llm_provider_requests.py`` — no live
network, no API keys). Ollama's failure path was the exact trigger for the F2
MeetUp (a live smoke test: ``sift triage --provider ollama`` with a missing
model -> 404 -> silent template fallback).
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sift.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _hermetic_sift_env(tmp_path, monkeypatch):
    """Isolate sift's app dir so a real ``~/.sift/config.yaml`` (e.g. the
    maintainer's own, which may have ``provider: anthropic`` set from real
    usage) never leaks into these tests. Same pattern/rationale as
    ``tests/test_main_ticket_integration.py::_hermetic_sift_env``: without
    this, a developer machine with a non-``template`` default provider would
    make an UNRELATED `sift triage` invocation (no ``--provider`` flag at
    all) silently attempt a real, unmocked LLM call.
    """
    app_dir = tmp_path / "sift_home"
    app_dir.mkdir()
    (app_dir / "config.yaml").write_text("cache_enabled: false\n")
    monkeypatch.setattr("sift.config._APP_DIR", app_dir)


_ALERTS_JSON = json.dumps(
    [
        {
            "id": "a1",
            "title": "Suspicious Login",
            "severity": "high",
            "source_ip": "203.0.113.15",
            "timestamp": "2026-01-01T10:00:00Z",
            "category": "authentication",
        },
        {
            "id": "a2",
            "title": "Brute Force Attempt",
            "severity": "high",
            "source_ip": "203.0.113.15",
            "timestamp": "2026-01-01T10:05:00Z",
            "category": "authentication",
        },
    ]
)


def _alert_file(tmp_path: Path) -> Path:
    f = tmp_path / "alerts.json"
    f.write_text(_ALERTS_JSON)
    return f


def _fail_ollama(monkeypatch, *, error: Exception | None = None) -> None:
    """Patch the urlopen seam OllamaSummarizer POSTs through so every Ollama
    call in the test raises (mirrors ``_install_fake_urlopen`` in
    ``tests/test_llm_provider_requests.py``, minus the request-capture)."""
    err = error or urllib.error.URLError("connection refused")

    def fake_urlopen(req, *args, **kwargs):
        raise err

    monkeypatch.setattr("sift.summarizers.ollama.urllib.request.urlopen", fake_urlopen)


# ---------------------------------------------------------------------------
# (a) + (c) — no template substitution, distinct exit code 4
# ---------------------------------------------------------------------------


class TestNoTemplateSubstitutionAndExitCode:
    def test_ollama_failure_exits_4_not_0_or_1(self, tmp_path, monkeypatch):
        """A requested-and-failed LLM provider must exit 4 — distinct from
        the cluster-priority codes (0/1) and the generic error code (2)."""
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "ollama", "-f", "json"],
        )
        assert result.exit_code == 4

    def test_ollama_failure_json_summary_is_null_not_template(self, tmp_path, monkeypatch):
        """The JSON output's `summary` must be null — never a template result
        silently standing in for the failed LLM call."""
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "ollama", "-f", "json"],
        )
        data = json.loads(result.stdout)
        assert data["summary"] is None
        # The rule-based cluster analysis itself is NOT thrown away.
        assert len(data["clusters"]) >= 1


# ---------------------------------------------------------------------------
# (a2) — a requested LLM provider whose SDK is NOT installed (ImportError at
# build time) is the SAME masquerade — must be loud + exit 4, never a silent
# template. Regression for the F2 Skeptic BLOCK (2026-07-03).
# ---------------------------------------------------------------------------


class TestProviderSdkNotInstalled:
    def _no_anthropic(self, monkeypatch):
        # Force the lazy `import anthropic` in AnthropicSummarizer.__init__ to
        # raise ImportError, simulating `pip install sift-triage` without [llm].
        monkeypatch.setitem(sys.modules, "anthropic", None)

    def test_missing_sdk_exits_4_not_0(self, tmp_path, monkeypatch):
        self._no_anthropic(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "anthropic", "-f", "json"],
        )
        assert result.exit_code == 4

    def test_missing_sdk_json_summary_null_not_template(self, tmp_path, monkeypatch):
        self._no_anthropic(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "anthropic", "-f", "json"],
        )
        data = json.loads(result.stdout)
        assert data["summary"] is None
        assert data["summary_provider"] == "anthropic"
        assert len(data["clusters"]) >= 1


# ---------------------------------------------------------------------------
# (b) — loud notice in rich AND md (not just html)
# ---------------------------------------------------------------------------


class TestLoudDefaultRenderers:
    def test_rich_format_shows_loud_unavailable_notice(self, tmp_path, monkeypatch):
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "ollama", "-f", "rich"],
        )
        assert "LLM SUMMARY UNAVAILABLE" in result.stdout  # in the RENDERER itself, not just stderr
        assert "ollama" in result.stdout
        assert result.exit_code == 4

    def test_console_format_shows_loud_unavailable_notice(self, tmp_path, monkeypatch):
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            [
                "triage",
                str(_alert_file(tmp_path)),
                "--quiet",
                "--summarize",
                "--provider",
                "ollama",
                "-f",
                "console",
            ],
        )
        assert "LLM SUMMARY UNAVAILABLE" in result.stdout
        assert result.exit_code == 4

    def test_md_format_shows_loud_unavailable_notice(self, tmp_path, monkeypatch):
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "ollama", "-f", "md"],
        )
        assert "LLM SUMMARY UNAVAILABLE" in result.stdout  # in the RENDERER itself, not just stderr
        assert "ollama" in result.stdout
        assert result.exit_code == 4

    def test_html_format_also_shows_unavailable_notice(self, tmp_path, monkeypatch):
        """Not required by F2 cut-1 (only rich/console/md are mandated — html
        already surfaced `provider` pre-F2), but kept consistent for free."""
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "ollama", "-f", "html"],
        )
        assert "LLM Summary Unavailable" in result.stdout
        assert result.exit_code == 4


# ---------------------------------------------------------------------------
# (d) — stderr-only; --format json stdout stays json.loads-parseable
# ---------------------------------------------------------------------------


class TestStderrOnlyJSONStaysParseable:
    def test_json_stdout_is_still_valid_json_on_llm_failure(self, tmp_path, monkeypatch):
        """The loud notice must never leak into stdout for --format json — a
        pipeline doing `sift triage ... -f json | jq` must never choke."""
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "ollama", "-f", "json"],
        )
        # Must not raise — stdout is exactly one JSON document, nothing else.
        data = json.loads(result.stdout)
        assert data["summary"] is None
        assert data["summary_error"] is not None
        assert data["summary_provider"] == "ollama"

    def test_json_failure_notice_appears_on_stderr_not_stdout(self, tmp_path, monkeypatch):
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "ollama", "-f", "json"],
        )
        assert "LLM SUMMARY UNAVAILABLE" not in result.stdout
        assert "LLM SUMMARY UNAVAILABLE" in result.stderr
        assert "ollama" in result.stderr


# ---------------------------------------------------------------------------
# (e) — a deliberate `--provider template` run is NOT degraded
# ---------------------------------------------------------------------------


class TestDeliberateTemplateIsNotDegraded:
    def test_deliberate_template_run_exits_normally_no_warning(self, tmp_path, monkeypatch):
        """No LLM was requested (provider=template, the default) — even
        though OllamaSummarizer is patched to fail, it's never invoked; this
        must behave exactly as a normal template run always has."""
        _fail_ollama(monkeypatch)  # proves it's simply never called
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "template", "-f", "json"],
        )
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        assert data["summary"] is not None
        assert data["summary"]["provider"] == "template"
        assert data["summary_error"] is None
        assert data["summary_provider"] is None
        assert "LLM SUMMARY UNAVAILABLE" not in result.stderr

    def test_no_summarize_flag_at_all_is_not_degraded(self, tmp_path):
        """The absolute baseline: no --summarize, no --provider at all."""
        result = runner.invoke(app, ["triage", str(_alert_file(tmp_path)), "--quiet", "-f", "json"])
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        assert data["summary_error"] is None
        assert "LLM SUMMARY UNAVAILABLE" not in result.stderr


# ---------------------------------------------------------------------------
# explicit --provider X failure is still the loud path (never silent) —
# no --on-llm-failure flag, no TTY prompt (both DEFERRED to slice-2)
# ---------------------------------------------------------------------------


class TestExplicitProviderFailureNeverSilent:
    def test_explicit_provider_flag_failure_is_loud_not_silent(self, tmp_path, monkeypatch):
        """An explicitly-named --provider that fails is a trust violation if
        silently substituted — must be loud, exactly like the config-default
        LLM-provider case. Note: `--provider` alone is a pre-existing no-op
        without `--summarize` (sift/main.py gates summarization on
        `summarize or cfg.summarize.provider != "template"`) — this test
        exercises the realistic "operator asked for an LLM" combination."""
        _fail_ollama(monkeypatch)
        result = runner.invoke(
            app,
            ["triage", str(_alert_file(tmp_path)), "--quiet", "--summarize", "--provider", "ollama", "-f", "json"],
        )
        assert result.exit_code == 4
        data = json.loads(result.stdout)
        assert data["summary"] is None

    def test_no_on_llm_failure_flag_exists(self):
        """F2 cut-1 explicitly DEFERS the --on-llm-failure=abort|template|prompt
        flag (and any TTY prompt) to slice-2 — assert it does not exist yet."""
        result = runner.invoke(app, ["triage", "--help"])
        assert "--on-llm-failure" not in result.stdout
