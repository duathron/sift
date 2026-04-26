"""Tests for TicketDraft, TicketResult, and TicketProvider protocol."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sift.ticketing.protocol import TicketDraft, TicketProvider, TicketResult


def _draft(**kwargs) -> TicketDraft:
    defaults = dict(
        title="[sift] CRITICAL | Credential Dumping",
        summary="Attack chain detected on dc01.",
        severity="CRITICAL",
        priority="IMMEDIATE",
        confidence=0.95,
        generated_at=datetime(2026, 4, 20, 10, 0, 0, tzinfo=timezone.utc),
        sift_version="1.1.0",
    )
    return TicketDraft(**(defaults | kwargs))


class TestTicketDraft:
    def test_minimal_valid(self):
        draft = _draft()
        assert draft.title == "[sift] CRITICAL | Credential Dumping"
        assert draft.severity == "CRITICAL"
        assert draft.iocs == []
        assert draft.recommendations == []

    def test_confidence_upper_bound_accepted(self):
        draft = _draft(confidence=1.0)
        assert draft.confidence == 1.0

    def test_confidence_lower_bound_accepted(self):
        draft = _draft(confidence=0.0)
        assert draft.confidence == 0.0

    def test_confidence_above_1_rejected(self):
        with pytest.raises(ValidationError):
            _draft(confidence=1.01)

    def test_confidence_below_0_rejected(self):
        with pytest.raises(ValidationError):
            _draft(confidence=-0.01)

    def test_optional_fields_populated(self):
        draft = _draft(
            iocs=["1.2.3.4", "evil.com"],
            technique_ids=["T1003", "T1021.001"],
            recommendations=["Isolate dc01", "Reset svc_admin"],
            timeline=["[10:00] [CRITICAL] Credential Dumping"],
            source_file="alerts.json",
        )
        assert len(draft.iocs) == 2
        assert draft.technique_ids == ["T1003", "T1021.001"]
        assert draft.source_file == "alerts.json"

    def test_evidence_defaults_to_empty_dict(self):
        draft = _draft()
        assert draft.evidence == {}


class TestTicketResult:
    def test_minimal(self):
        result = TicketResult(provider="dry-run")
        assert result.ticket_id is None
        assert result.ticket_url is None
        assert result.raw_response == {}

    def test_with_all_fields(self):
        result = TicketResult(
            provider="thehive",
            ticket_id="alert-42",
            ticket_url="https://thehive.example.com/alerts/alert-42/details",
            raw_response={"_id": "alert-42"},
        )
        assert result.ticket_id == "alert-42"
        assert "thehive" in result.ticket_url


class TestTicketProviderProtocol:
    def test_dry_run_satisfies_protocol(self):
        from sift.ticketing.dry_run import DryRunProvider
        assert isinstance(DryRunProvider(), TicketProvider)
