"""False-positive gate: benign fixtures must produce prompts with no CRITICAL finding and no redaction.

A plain guard (green on main by design): it fails if the final-prompt scan starts
blanking text of the shipped benign fixtures.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from shipwright_kit.security.injection import SeverityLevel
from shipwright_kit.security.injection import scan as kit_scan
from typer.testing import CliRunner

import sift.main as main_mod
from sift.main import app
from sift.summarizers.prompt import build_cluster_prompt

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


@pytest.mark.parametrize("fixture", sorted(p.name for p in FIXTURES.glob("*.json")))
def test_benign_fixture_prompt_has_no_critical_and_no_redaction(fixture, monkeypatch):
    seen: list[str] = []

    class _Stub:
        def __init__(self, cfg):
            self.cfg = cfg

        def summarize(self, report):
            seen.append(build_cluster_prompt(report, self.cfg.summarize))
            return None

    real = main_mod._build_summarizer

    def wrapped(provider, cfg, **kw):
        real(provider, cfg, **kw)
        return _Stub(cfg)

    monkeypatch.setattr(main_mod, "_build_summarizer", wrapped)
    r = runner.invoke(
        app, ["triage", str(FIXTURES / fixture), "-f", "json", "--summarize", "--provider", "mock", "--no-cache"]
    )
    assert r.exception is None or isinstance(r.exception, SystemExit), r.exception
    assert seen
    for prompt in seen:
        assert not [f for f in kit_scan(prompt) if f.severity is SeverityLevel.CRITICAL]
        assert "[REDACTED" not in prompt
