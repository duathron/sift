"""Cluster label/reason/IOC text must honour the config-sourced ``summarize.redact_fields``.

The alert-level redaction already blanked per-alert fields in the prompt, but the
cluster label, cluster reason and IOC preview carried the same values verbatim.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import sift.main as main_mod
from sift.config import SummarizeConfig
from sift.main import app
from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority, TriageReport
from sift.summarizers.prompt import build_cluster_prompt

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()

_T = datetime(2026, 3, 22, 9, 0, 0, tzinfo=timezone.utc)


def _report(label: str, reason: str, iocs: list[str] | None = None) -> TriageReport:
    alert = Alert(
        id="a1",
        timestamp=_T,
        severity=AlertSeverity.HIGH,
        title="Mimikatz on WORKSTATION01",
        source="edr",
        source_ip="10.10.5.42",
        dest_ip="10.10.3.20",
        host="WORKSTATION01",
        category="credential_access",
    )
    cluster = Cluster(
        id="c1",
        label=label,
        alerts=[alert],
        priority=ClusterPriority.HIGH,
        score=50.0,
        iocs=iocs or [],
        cluster_reason=reason,
        first_seen=_T,
        last_seen=_T,
    )
    return TriageReport(
        input_file="x.json",
        alerts_ingested=1,
        alerts_after_dedup=1,
        clusters=[cluster],
        analyzed_at=_T,
    )


def test_cluster_label_and_reason_redacted_when_fields_redacted():
    report = _report(
        "Mimikatz on WORKSTATION01",
        "source/dest IP pair: 10.10.5.42 → 10.10.3.20",
        iocs=["10.10.5.42", "10.10.3.20"],
    )
    prompt = build_cluster_prompt(report, SummarizeConfig(redact_fields=["title", "source_ip", "dest_ip", "host"]))
    for needle in ("Mimikatz", "10.10.5.42", "10.10.3.20", "WORKSTATION01"):
        assert needle not in prompt
    assert "[label redacted]" in prompt
    assert "[reason redacted]" in prompt
    assert "- IOCs        : [redacted]" in prompt


def test_constant_reasons_survive_redaction():
    report = _report("Other (3 alerts)", "max_clusters limit reached; grouped as Other")
    prompt = build_cluster_prompt(report, SummarizeConfig(redact_fields=["user"]))
    assert "Other (3 alerts)" in prompt
    assert "max_clusters limit reached; grouped as Other" in prompt

    report = _report("Failed login", "singleton")
    prompt = build_cluster_prompt(report, SummarizeConfig(redact_fields=["user"]))
    assert "- Reason      : singleton" in prompt


def test_no_redaction_prompt_unchanged():
    report = _report("Mimikatz on WORKSTATION01", "IOC overlap: 10.10.5.42", iocs=["10.10.5.42"])
    prompt = build_cluster_prompt(report, SummarizeConfig(redact_fields=[]))
    assert "### Cluster c1 — Mimikatz on WORKSTATION01" in prompt
    assert "- Reason      : IOC overlap: 10.10.5.42" in prompt
    assert "- IOCs        : 10.10.5.42" in prompt
    assert "[label redacted]" not in prompt
    assert "[reason redacted]" not in prompt


# ---------------------------------------------------------------------------
# End to end through --config and a spying summarizer
# ---------------------------------------------------------------------------


def _capture_prompt(monkeypatch) -> list[str]:
    prompts: list[str] = []
    real = main_mod._build_summarizer

    class _Spy:
        def __init__(self, cfg):
            self.cfg = cfg

        def summarize(self, report):
            prompts.append(build_cluster_prompt(report, self.cfg.summarize))
            return None

    def wrapped(provider, cfg, **kw):
        real(provider, cfg, **kw)
        return _Spy(cfg)

    monkeypatch.setattr(main_mod, "_build_summarizer", wrapped)
    return prompts


def _run_with_config(tmp_path, monkeypatch, fixture: str, fields: list[str], *extra: str) -> str:
    prompts = _capture_prompt(monkeypatch)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({"summarize": {"redact_fields": fields}}))
    r = runner.invoke(
        app,
        [
            "triage",
            str(FIXTURES / fixture),
            "--config",
            str(cfg),
            "--no-cache",
            "--summarize",
            "--provider",
            "mock",
            *extra,
        ],
    )
    assert r.exit_code in (0, 1), r.output
    assert len(prompts) == 1
    return prompts[0]


def test_config_redact_fields_five_fields_leave_no_identity_in_prompt(tmp_path, monkeypatch):
    prompt = _run_with_config(
        tmp_path, monkeypatch, "lateral_movement.json", ["title", "source_ip", "dest_ip", "user", "host"]
    )
    for needle in ("10.10.5.42", "10.10.3.20", "bob.harris"):
        assert prompt.count(needle) == 0, needle


def test_config_redact_fields_user_only_hides_user_from_prompt(tmp_path, monkeypatch):
    prompt = _run_with_config(tmp_path, monkeypatch, "lateral_movement.json", ["user"])
    assert prompt.count("bob.harris") == 0


@pytest.mark.parametrize("fixture", ["mixed.json", "fp_cluster.json"])
def test_config_redact_category_hides_category_from_label_and_reason(tmp_path, monkeypatch, fixture):
    alerts = json.loads((FIXTURES / fixture).read_text())
    categories = {a["category"] for a in alerts if a.get("category")}
    prompt = _run_with_config(tmp_path, monkeypatch, fixture, ["category"])
    text = "\n".join(line for line in prompt.splitlines() if line.startswith(("### Cluster", "- Reason")))
    assert text
    for cat in categories:
        assert cat not in text


def test_cli_redact_fields_not_merged_into_summarize_config(tmp_path, monkeypatch):
    seen: list[list[str]] = []
    real = main_mod._build_summarizer

    def wrapped(provider, cfg, **kw):
        seen.append(list(cfg.summarize.redact_fields))
        return real(provider, cfg, **kw)

    monkeypatch.setattr(main_mod, "_build_summarizer", wrapped)
    r = runner.invoke(
        app,
        [
            "triage",
            str(FIXTURES / "lateral_movement.json"),
            "--no-cache",
            "--summarize",
            "--provider",
            "mock",
            "--redact-fields",
            "source_ip,user",
        ],
    )
    assert r.exit_code in (0, 1), r.output
    assert seen == [[]]
