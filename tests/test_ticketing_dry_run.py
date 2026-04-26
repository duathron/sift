"""Tests for DryRunProvider."""

import json
from datetime import datetime, timezone
from pathlib import Path

from sift.ticketing.dry_run import DryRunProvider
from sift.ticketing.protocol import TicketDraft


def _draft() -> TicketDraft:
    return TicketDraft(
        title="[sift] HIGH | Brute Force + Account Lockout",
        summary="SSH brute force followed by account lockout on dc01.",
        severity="HIGH",
        priority="WITHIN_1H",
        confidence=0.80,
        iocs=["185.220.101.47"],
        technique_ids=["T1110.001"],
        recommendations=["Block 185.220.101.47", "Reset jdoe password"],
        generated_at=datetime(2026, 4, 20, 10, 0, 0, tzinfo=timezone.utc),
        sift_version="1.1.0",
    )


class TestDryRunProvider:
    def test_healthcheck_always_true(self):
        provider = DryRunProvider()
        ok, msg = provider.healthcheck()
        assert ok is True
        assert "dry-run" in msg

    def test_name(self):
        assert DryRunProvider.name == "dry-run"

    def test_send_to_stdout_returns_result(self, capsys):
        provider = DryRunProvider()
        result = provider.send(_draft())
        assert result.provider == "dry-run"
        assert result.ticket_id is None

    def test_send_to_stdout_valid_json(self, capsys):
        provider = DryRunProvider()
        provider.send(_draft())
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["title"] == "[sift] HIGH | Brute Force + Account Lockout"
        assert data["severity"] == "HIGH"
        assert data["confidence"] == 0.80

    def test_send_to_file(self, tmp_path: Path):
        out = tmp_path / "ticket.json"
        provider = DryRunProvider(output_path=out)
        result = provider.send(_draft())
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["priority"] == "WITHIN_1H"
        assert result.ticket_url is not None
        assert "ticket.json" in result.ticket_url

    def test_send_to_file_contains_iocs(self, tmp_path: Path):
        out = tmp_path / "ticket.json"
        DryRunProvider(output_path=out).send(_draft())
        data = json.loads(out.read_text())
        assert "185.220.101.47" in data["iocs"]

    def test_raw_response_matches_payload(self, capsys):
        provider = DryRunProvider()
        result = provider.send(_draft())
        assert result.raw_response["severity"] == "HIGH"
        assert result.raw_response["sift_version"] == "1.1.0"

    def test_stdout_no_file_url(self, capsys):
        provider = DryRunProvider()
        result = provider.send(_draft())
        assert result.ticket_url is None
