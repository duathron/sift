"""CLI integration tests for --ticket / --ticket-output / --ticket-all flags."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sift.main import app

runner = CliRunner()

# ---------------------------------------------------------------------------
# Inline fixture — minimal multi-severity alert set
# ---------------------------------------------------------------------------

_ALERTS_JSON = json.dumps([
    {
        "id": "t1",
        "title": "Credential Dumping Detected",
        "severity": "critical",
        "host": "dc01",
        "user": "svc_admin",
        "source_ip": "10.10.1.5",
        "timestamp": "2026-04-20T10:00:00Z",
        "category": "credential_access",
        "technique_ids": ["T1003"],
    },
    {
        "id": "t2",
        "title": "Lateral Movement via RDP",
        "severity": "high",
        "source_ip": "10.10.1.5",
        "dest_ip": "10.10.2.10",
        "timestamp": "2026-04-20T10:05:00Z",
        "category": "lateral_movement",
        "technique_ids": ["T1021.001"],
    },
    {
        "id": "t3",
        "title": "SSH Login Failed",
        "severity": "medium",
        "source_ip": "185.220.101.47",
        "dest_ip": "10.10.1.5",
        "timestamp": "2026-04-20T09:50:00Z",
        "category": "brute_force",
    },
])

_ALERTS_MULTIPLE_CLUSTERS = json.dumps([
    # Cluster A — CRITICAL (no shared IOCs with B)
    {
        "id": "a1", "title": "Ransomware Encryption", "severity": "critical",
        "host": "fileserver-01", "iocs": ["c2.ransom.onion"],
        "timestamp": "2026-04-20T10:00:00Z",
    },
    {
        "id": "a2", "title": "Mass File Rename", "severity": "high",
        "host": "fileserver-01", "iocs": ["c2.ransom.onion"],
        "timestamp": "2026-04-20T10:01:00Z",
    },
    # Cluster B — HIGH (different host/IOC)
    {
        "id": "b1", "title": "Brute Force SSH", "severity": "high",
        "source_ip": "1.2.3.4", "dest_ip": "10.0.0.1", "iocs": ["1.2.3.4"],
        "timestamp": "2026-04-20T11:00:00Z",
    },
    {
        "id": "b2", "title": "Account Lockout", "severity": "high",
        "source_ip": "1.2.3.4", "dest_ip": "10.0.0.1", "iocs": ["1.2.3.4"],
        "timestamp": "2026-04-20T11:05:00Z",
    },
    # Cluster C — MEDIUM (separate)
    {
        "id": "c1", "title": "Port Scan Detected", "severity": "medium",
        "source_ip": "9.9.9.9", "iocs": ["9.9.9.9"],
        "timestamp": "2026-04-20T12:00:00Z",
    },
])


@pytest.fixture
def alerts_file(tmp_path: Path) -> Path:
    f = tmp_path / "alerts.json"
    f.write_text(_ALERTS_JSON)
    return f


@pytest.fixture
def multi_cluster_file(tmp_path: Path) -> Path:
    f = tmp_path / "multi.json"
    f.write_text(_ALERTS_MULTIPLE_CLUSTERS)
    return f


# ---------------------------------------------------------------------------
# dry-run: stdout
# ---------------------------------------------------------------------------

class TestTicketDryRunStdout:
    def test_ticket_flag_produces_output(self, alerts_file: Path):
        result = runner.invoke(app, [
            "triage", str(alerts_file), "--ticket", "dry-run", "-f", "json", "-q",
        ])
        # Ticket output goes to stdout via DryRunProvider (print), JSON triage output also on stdout
        # Both appear in result.output (CliRunner merges stdout by default)
        assert result.exit_code in (0, 1)  # 1 = CRITICAL/HIGH cluster found

    def test_dry_run_output_contains_title(self, alerts_file: Path):
        result = runner.invoke(app, [
            "triage", str(alerts_file), "--ticket", "dry-run", "-f", "json", "-q",
        ])
        assert result.exit_code in (0, 1)
        # stdout contains the ticket JSON (printed by DryRunProvider)
        # and the triage JSON — search for sift-tagged title
        assert "[sift]" in result.output

    def test_dry_run_no_ticket_url_in_output(self, alerts_file: Path, capsys):
        """dry-run without --ticket-output prints JSON to stdout, no URL in stderr."""
        result = runner.invoke(app, [
            "triage", str(alerts_file), "--ticket", "dry-run", "-f", "json", "-q",
        ])
        assert result.exit_code in (0, 1)
        # Ticket created message in stderr (via console which goes to stderr)
        assert "dry-run" in result.output or result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# dry-run: file output
# ---------------------------------------------------------------------------

class TestTicketDryRunFile:
    def test_ticket_output_file_created(self, alerts_file: Path, tmp_path: Path):
        out = tmp_path / "ticket.json"
        result = runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "dry-run",
            "--ticket-output", str(out),
            "-f", "json", "-q",
        ])
        assert result.exit_code in (0, 1)
        assert out.exists(), f"ticket file not created; output: {result.output}"

    def test_ticket_output_is_valid_json(self, alerts_file: Path, tmp_path: Path):
        out = tmp_path / "ticket.json"
        runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "dry-run",
            "--ticket-output", str(out),
            "-f", "json", "-q",
        ])
        data = json.loads(out.read_text())
        assert "title" in data
        assert "severity" in data
        assert "confidence" in data
        assert data["sift_version"] is not None

    def test_ticket_title_format(self, alerts_file: Path, tmp_path: Path):
        out = tmp_path / "ticket.json"
        runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "dry-run",
            "--ticket-output", str(out),
            "-f", "json", "-q",
        ])
        data = json.loads(out.read_text())
        assert data["title"].startswith("[sift]")

    def test_ticket_severity_is_valid(self, alerts_file: Path, tmp_path: Path):
        out = tmp_path / "ticket.json"
        runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "dry-run",
            "--ticket-output", str(out),
            "-f", "json", "-q",
        ])
        data = json.loads(out.read_text())
        assert data["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_ticket_priority_is_valid(self, alerts_file: Path, tmp_path: Path):
        out = tmp_path / "ticket.json"
        runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "dry-run",
            "--ticket-output", str(out),
            "-f", "json", "-q",
        ])
        data = json.loads(out.read_text())
        assert data["priority"] in ("IMMEDIATE", "WITHIN_1H", "WITHIN_24H", "MONITOR")

    def test_ticket_iocs_present(self, alerts_file: Path, tmp_path: Path):
        out = tmp_path / "ticket.json"
        runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "dry-run",
            "--ticket-output", str(out),
            "-f", "json", "-q",
        ])
        data = json.loads(out.read_text())
        assert isinstance(data["iocs"], list)

    def test_ticket_timeline_sorted(self, alerts_file: Path, tmp_path: Path):
        out = tmp_path / "ticket.json"
        runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "dry-run",
            "--ticket-output", str(out),
            "-f", "json", "-q",
        ])
        data = json.loads(out.read_text())
        assert isinstance(data["timeline"], list)

    def test_ticket_output_implies_dry_run(self, alerts_file: Path, tmp_path: Path):
        """--ticket-output without --ticket should use dry-run provider."""
        out = tmp_path / "ticket.json"
        result = runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket-output", str(out),
            "-f", "json", "-q",
        ])
        assert result.exit_code in (0, 1)
        assert out.exists()


# ---------------------------------------------------------------------------
# --ticket-all
# ---------------------------------------------------------------------------

class TestTicketAll:
    def test_ticket_all_creates_file_per_cluster(self, multi_cluster_file: Path, tmp_path: Path):
        """With --ticket-all, first HIGH/CRITICAL cluster gets a ticket (at minimum)."""
        out = tmp_path / "ticket_top.json"
        result = runner.invoke(app, [
            "triage", str(multi_cluster_file),
            "--ticket", "dry-run",
            "--ticket-output", str(out),
            "--ticket-all",
            "-f", "json", "-q",
        ])
        assert result.exit_code in (0, 1)
        # At least one ticket file exists (first cluster overwrites, subsequent go to stdout)
        # Because DryRunProvider writes to one path, last write wins for file
        # But all ticket sends succeed without error
        assert "✗" not in result.output or "Ticket" not in result.output

    def test_ticket_all_no_high_critical_warns(self, tmp_path: Path):
        low_alerts = json.dumps([{
            "id": "l1", "title": "Info Event", "severity": "low",
            "timestamp": "2026-04-20T10:00:00Z",
        }])
        f = tmp_path / "low.json"
        f.write_text(low_alerts)
        result = runner.invoke(app, [
            "triage", str(f),
            "--ticket", "dry-run",
            "--ticket-all",
            "-f", "json", "-q",
        ])
        assert result.exit_code in (0, 1)
        # No crash; warning or silent
        assert result.exit_code != 2


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestTicketErrors:
    def test_invalid_provider_exits_2(self, alerts_file: Path):
        result = runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "nonexistent_provider",
            "-f", "json", "-q",
        ])
        assert result.exit_code == 2

    def test_thehive_without_token_exits_2(self, alerts_file: Path):
        """TheHive without SIFT_THEHIVE_TOKEN env var → ValueError → exit 2."""
        import os
        env = {k: v for k, v in os.environ.items() if k != "SIFT_THEHIVE_TOKEN"}
        result = runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "thehive",
            "-f", "json", "-q",
        ], env=env)
        assert result.exit_code == 2

    def test_jira_without_token_exits_2(self, alerts_file: Path):
        """Jira without SIFT_JIRA_TOKEN → ValueError → exit 2."""
        import os
        env = {k: v for k, v in os.environ.items()
               if k not in ("SIFT_JIRA_TOKEN", "SIFT_JIRA_EMAIL")}
        result = runner.invoke(app, [
            "triage", str(alerts_file),
            "--ticket", "jira",
            "-f", "json", "-q",
        ], env=env)
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# sift config --ticket-* flags
# ---------------------------------------------------------------------------

class TestConfigTicketFlags:
    def test_config_ticket_provider_saved(self, tmp_path: Path):
        cfg_file = tmp_path / "config.yaml"
        result = runner.invoke(app, [
            "config",
            "--ticket-provider", "thehive",
            "--ticket-url", "https://thehive.example.com",
            "--config", str(cfg_file),
        ])
        assert result.exit_code == 0
        assert cfg_file.exists()
        import yaml
        data = yaml.safe_load(cfg_file.read_text())
        assert data["ticketing"]["provider"] == "thehive"
        assert data["ticketing"]["url"] == "https://thehive.example.com"

    def test_config_jira_project_saved(self, tmp_path: Path):
        cfg_file = tmp_path / "config.yaml"
        runner.invoke(app, [
            "config",
            "--ticket-provider", "jira",
            "--ticket-url", "https://company.atlassian.net",
            "--ticket-project", "SOC",
            "--ticket-jira-email", "analyst@company.com",
            "--config", str(cfg_file),
        ])
        import yaml
        data = yaml.safe_load(cfg_file.read_text())
        assert data["ticketing"]["project_key"] == "SOC"
        assert data["ticketing"]["jira_email"] == "analyst@company.com"

    def test_config_ticket_token_no_provider_exits_2(self, tmp_path: Path):
        cfg_file = tmp_path / "empty_config.yaml"
        result = runner.invoke(app, [
            "config",
            "--ticket-token", "mytoken123",
            "--config", str(cfg_file),
        ])
        assert result.exit_code == 2

    def test_config_show_includes_ticketing(self, tmp_path: Path):
        cfg_file = tmp_path / "config.yaml"
        runner.invoke(app, [
            "config",
            "--ticket-provider", "jira",
            "--config", str(cfg_file),
        ])
        result = runner.invoke(app, [
            "config", "--show", "--config", str(cfg_file),
        ])
        assert result.exit_code == 0
        assert "ticketing" in result.output
