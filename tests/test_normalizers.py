"""Tests for sift normalizers."""

from __future__ import annotations

import json

import pytest

from sift.models import AlertSeverity
from sift.normalizers.generic import GenericNormalizer
from sift.normalizers.splunk import SplunkNormalizer
from sift.normalizers.csv_normalizer import CSVNormalizer


# ---------------------------------------------------------------------------
# GenericNormalizer
# ---------------------------------------------------------------------------

class TestGenericNormalizer:
    norm = GenericNormalizer()

    def test_name(self):
        assert self.norm.name == "generic"

    def test_can_handle_json_object(self):
        assert self.norm.can_handle('{"title": "test"}')

    def test_can_handle_json_array(self):
        assert self.norm.can_handle('[{"title": "a"}, {"title": "b"}]')

    def test_cannot_handle_plain_text(self):
        assert not self.norm.can_handle("not json at all")

    def test_single_alert(self):
        raw = json.dumps({"id": "A1", "title": "Test Alert", "severity": "HIGH"})
        alerts = self.norm.normalize(raw)
        assert len(alerts) == 1
        assert alerts[0].title == "Test Alert"
        assert alerts[0].severity == AlertSeverity.HIGH

    def test_alert_array(self):
        raw = json.dumps([
            {"title": "Alert 1", "severity": "LOW"},
            {"title": "Alert 2", "severity": "CRITICAL"},
        ])
        alerts = self.norm.normalize(raw)
        assert len(alerts) == 2
        assert alerts[1].severity == AlertSeverity.CRITICAL

    def test_severity_mapping(self):
        cases = [
            ("critical", AlertSeverity.CRITICAL),
            ("CRITICAL", AlertSeverity.CRITICAL),
            ("high", AlertSeverity.HIGH),
            ("medium", AlertSeverity.MEDIUM),
            ("low", AlertSeverity.LOW),
            ("info", AlertSeverity.INFO),
            ("informational", AlertSeverity.INFO),
        ]
        for raw_sev, expected in cases:
            raw = json.dumps({"title": "x", "severity": raw_sev})
            alerts = self.norm.normalize(raw)
            assert alerts[0].severity == expected, f"Failed for {raw_sev}"

    def test_numeric_severity(self):
        raw = json.dumps({"title": "x", "severity": 1})
        alerts = self.norm.normalize(raw)
        assert alerts[0].severity == AlertSeverity.CRITICAL

    def test_ip_field_aliases(self):
        raw = json.dumps({"title": "x", "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"})
        alerts = self.norm.normalize(raw)
        assert alerts[0].source_ip == "10.0.0.1"
        assert alerts[0].dest_ip == "8.8.8.8"

    def test_empty_array(self):
        alerts = self.norm.normalize("[]")
        assert alerts == []

    def test_invalid_json_returns_empty(self):
        alerts = self.norm.normalize("this is not json {{{")
        assert alerts == []

    def test_raw_field_preserved(self):
        data = {"title": "x", "custom_field": "custom_value"}
        alerts = self.norm.normalize(json.dumps(data))
        assert alerts[0].raw["custom_field"] == "custom_value"


# ---------------------------------------------------------------------------
# SplunkNormalizer
# ---------------------------------------------------------------------------

class TestSplunkNormalizer:
    norm = SplunkNormalizer()

    def test_name(self):
        assert self.norm.name == "splunk"

    def test_can_handle_splunk_format(self):
        raw = json.dumps({"results": [], "preview": False})
        assert self.norm.can_handle(raw)

    def test_cannot_handle_plain_json(self):
        raw = json.dumps([{"title": "x"}])
        assert not self.norm.can_handle(raw)

    def test_splunk_notable_fields(self):
        raw = json.dumps({
            "results": [{
                "rule_name": "Phishing Detected",
                "urgency": "high",
                "_time": "2026-03-22T10:00:00Z",
                "src": "10.0.0.1",
                "dest": "185.220.101.47",
                "user": "jdoe",
                "host": "WORKSTATION01",
            }]
        })
        alerts = self.norm.normalize(raw)
        assert len(alerts) == 1
        a = alerts[0]
        assert a.title == "Phishing Detected"
        assert a.severity == AlertSeverity.HIGH
        assert a.source_ip == "10.0.0.1"
        assert a.dest_ip == "185.220.101.47"
        assert a.user == "jdoe"

    def test_empty_results(self):
        raw = json.dumps({"results": []})
        alerts = self.norm.normalize(raw)
        assert alerts == []


# ---------------------------------------------------------------------------
# CSVNormalizer
# ---------------------------------------------------------------------------

class TestCSVNormalizer:
    norm = CSVNormalizer()

    def test_name(self):
        assert self.norm.name == "csv"

    def test_can_handle_csv(self):
        csv = "title,severity,source_ip\nAlert 1,HIGH,10.0.0.1\n"
        assert self.norm.can_handle(csv)

    def test_basic_csv(self):
        csv = "title,severity,source_ip,dest_ip\nAlert 1,HIGH,10.0.0.1,8.8.8.8\nAlert 2,LOW,10.0.0.2,1.1.1.1\n"
        alerts = self.norm.normalize(csv)
        assert len(alerts) == 2
        assert alerts[0].title == "Alert 1"
        assert alerts[0].severity == AlertSeverity.HIGH
        assert alerts[0].source_ip == "10.0.0.1"

    def test_case_insensitive_headers(self):
        csv = "TITLE,SEVERITY\nTest,critical\n"
        alerts = self.norm.normalize(csv)
        assert alerts[0].severity == AlertSeverity.CRITICAL
