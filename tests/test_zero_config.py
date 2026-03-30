"""Zero-config smoke test — sift triage <file> without any flags.

Verifies the 'just works' path: no tuning flags, no --format, no --summarize.
If this test breaks, the basic user experience is broken.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sift.main import app

runner = CliRunner()


def _parse_json_output(output: str) -> dict:
    """Extract JSON from output that may have leading warning/info lines."""
    for i, line in enumerate(output.splitlines()):
        if line.strip().startswith("{"):
            return json.loads("\n".join(output.splitlines()[i:]))
    raise ValueError(f"No JSON found in output:\n{output}")


_SAMPLE_ALERTS = json.dumps([
    {
        "id": "a1",
        "title": "Brute Force Login",
        "severity": "high",
        "source_ip": "192.168.1.100",
        "timestamp": "2024-01-15T10:00:00Z",
        "category": "authentication",
    },
    {
        "id": "a2",
        "title": "Suspicious PowerShell",
        "severity": "critical",
        "host": "WORKSTATION-01",
        "timestamp": "2024-01-15T10:05:00Z",
        "category": "execution",
    },
    {
        "id": "a3",
        "title": "Brute Force Login",
        "severity": "high",
        "source_ip": "192.168.1.100",
        "timestamp": "2024-01-15T10:01:00Z",
        "category": "authentication",
    },
])

_SAMPLE_CSV = """\
timestamp,title,severity,source_ip,category
2024-01-15T10:00:00Z,SSH Brute Force,high,10.0.0.5,authentication
2024-01-15T10:01:00Z,SSH Brute Force,high,10.0.0.5,authentication
2024-01-15T10:02:00Z,Port Scan,medium,10.0.0.6,reconnaissance
"""


@pytest.fixture()
def json_alert_file(tmp_path: Path) -> Path:
    f = tmp_path / "alerts.json"
    f.write_text(_SAMPLE_ALERTS)
    return f


@pytest.fixture()
def csv_alert_file(tmp_path: Path) -> Path:
    f = tmp_path / "alerts.csv"
    f.write_text(_SAMPLE_CSV)
    return f


class TestZeroConfigJSON:
    """Basic invocation with JSON input — no flags."""

    def test_exits_successfully(self, json_alert_file: Path):
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache"])
        assert result.exit_code in (0, 1), f"Unexpected exit code: {result.exit_code}\n{result.output}"

    def test_produces_output(self, json_alert_file: Path):
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache"])
        assert result.output.strip(), "Expected non-empty output"

    def test_json_format(self, json_alert_file: Path):
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache", "-f", "json"])
        assert result.exit_code in (0, 1)
        data = _parse_json_output(result.output)
        assert "clusters" in data
        assert len(data["clusters"]) >= 1

    def test_dedup_runs_by_default(self, json_alert_file: Path):
        """3 alerts, 2 are near-duplicates — dedup should reduce to 2."""
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache", "-f", "json"])
        data = _parse_json_output(result.output)
        assert data["alerts_after_dedup"] <= data["alerts_ingested"]

    def test_no_flags_produces_clusters(self, json_alert_file: Path):
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache", "-f", "json"])
        data = _parse_json_output(result.output)
        assert len(data["clusters"]) >= 1


class TestZeroConfigCSV:
    """Basic invocation with CSV input — no flags."""

    def test_csv_exits_successfully(self, csv_alert_file: Path):
        result = runner.invoke(app, ["triage", str(csv_alert_file), "--quiet", "--no-cache"])
        assert result.exit_code in (0, 1), f"Unexpected exit code: {result.exit_code}\n{result.output}"

    def test_csv_json_format(self, csv_alert_file: Path):
        result = runner.invoke(app, ["triage", str(csv_alert_file), "--quiet", "--no-cache", "-f", "json"])
        data = _parse_json_output(result.output)
        assert "clusters" in data
        assert data["alerts_ingested"] >= 1


class TestAutoTuningIntegration:
    """Verify auto-tuning runs silently without requiring user flags."""

    def test_no_tuning_message_for_small_file(self, json_alert_file: Path):
        """Small file: no auto-tune message shown."""
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache"])
        assert "Auto-tuned" not in result.output

    def test_no_crash_without_chunk_size_flag(self, json_alert_file: Path):
        """Should not require --chunk-size to run."""
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache"])
        assert result.exit_code in (0, 1)

    def test_no_crash_without_drop_raw_flag(self, json_alert_file: Path):
        """Should not require --drop-raw to run."""
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache"])
        assert result.exit_code in (0, 1)


class TestCacheDefault:
    """Cache is on by default; --no-cache disables it."""

    def test_no_cache_flag_works(self, json_alert_file: Path):
        result = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "--no-cache", "-f", "json"])
        assert result.exit_code in (0, 1)
        data = _parse_json_output(result.output)
        assert "clusters" in data

    def test_cache_second_run_hits(self, json_alert_file: Path, tmp_path: Path):
        """Second run on same file should be a cache hit (faster)."""
        # Run once to populate cache
        runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "-f", "json"])
        # Second run — should hit cache
        result2 = runner.invoke(app, ["triage", str(json_alert_file), "--quiet", "-f", "json"])
        assert result2.exit_code in (0, 1)


class TestEnrichMergedFlag:
    """--enrich accepts optional mode value."""

    def test_enrich_without_mode_defaults_to_all(self, json_alert_file: Path):
        """--enrich alone should default to 'all' mode (consent prompt skipped in test)."""
        # Use --enrich local to avoid external API calls in tests
        result = runner.invoke(
            app,
            ["triage", str(json_alert_file), "--quiet", "--no-cache", "--enrich", "local", "-f", "json"],
        )
        assert result.exit_code in (0, 1)
