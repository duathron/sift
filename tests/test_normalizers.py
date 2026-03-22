"""Tests for sift normalizers — GenericNormalizer, SplunkNormalizer, CSVNormalizer."""

from __future__ import annotations

import json

import pytest

from sift.models import Alert, AlertSeverity
from sift.normalizers.csv_normalizer import CSVNormalizer
from sift.normalizers.generic import GenericNormalizer
from sift.normalizers.splunk import SplunkNormalizer


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _json_array(*records: dict) -> str:
    return json.dumps(list(records))


def _json_object(**fields) -> str:
    return json.dumps(fields)


# ---------------------------------------------------------------------------
# GenericNormalizer — can_handle
# ---------------------------------------------------------------------------


class TestGenericNormalizerCanHandle:
    norm = GenericNormalizer()

    def test_can_handle_json_object(self):
        assert self.norm.can_handle('{"title": "test"}')

    def test_can_handle_json_array(self):
        assert self.norm.can_handle('[{"title": "a"}, {"title": "b"}]')

    def test_can_handle_empty_array(self):
        # Valid JSON — should be accepted by can_handle even if normalize returns []
        assert self.norm.can_handle("[]")

    def test_cannot_handle_csv(self):
        assert not self.norm.can_handle("title,severity\nAlert 1,HIGH\n")

    def test_cannot_handle_garbage(self):
        assert not self.norm.can_handle("not json at all }{][")

    def test_cannot_handle_plain_string(self):
        assert not self.norm.can_handle('"just a string"')

    def test_cannot_handle_empty_string(self):
        assert not self.norm.can_handle("")


# ---------------------------------------------------------------------------
# GenericNormalizer — normalize: basic counts and empty inputs
# ---------------------------------------------------------------------------


class TestGenericNormalizerNormalize:
    norm = GenericNormalizer()

    def test_normalize_json_array_three_alerts(self):
        raw = _json_array(
            {"title": "Alert A", "severity": "low"},
            {"title": "Alert B", "severity": "medium"},
            {"title": "Alert C", "severity": "high"},
        )
        alerts = self.norm.normalize(raw)
        assert len(alerts) == 3
        assert all(isinstance(a, Alert) for a in alerts)

    def test_normalize_single_json_object_returns_one_alert(self):
        raw = _json_object(id="singleton-1", title="Solo Alert", severity="high")
        alerts = self.norm.normalize(raw)
        assert len(alerts) == 1
        assert alerts[0].title == "Solo Alert"

    def test_normalize_empty_string_returns_empty_list(self):
        assert self.norm.normalize("") == []

    def test_normalize_invalid_json_returns_empty_list(self):
        assert self.norm.normalize("not json") == []

    def test_normalize_preserves_raw_field(self):
        data = {"title": "x", "custom_key": "custom_value"}
        alerts = self.norm.normalize(json.dumps(data))
        assert alerts[0].raw["custom_key"] == "custom_value"

    def test_normalize_titles_from_three_alerts(self):
        raw = _json_array(
            {"title": "First"},
            {"title": "Second"},
            {"title": "Third"},
        )
        titles = [a.title for a in self.norm.normalize(raw)]
        assert titles == ["First", "Second", "Third"]


# ---------------------------------------------------------------------------
# GenericNormalizer — field mapping
# ---------------------------------------------------------------------------


class TestGenericNormalizerFieldMapping:
    norm = GenericNormalizer()

    def test_field_id(self):
        raw = _json_object(id="ABC-001", title="t")
        assert self.norm.normalize(raw)[0].id == "ABC-001"

    def test_field_id_alias_alert_id(self):
        raw = _json_object(alert_id="ALT-ID", title="t")
        assert self.norm.normalize(raw)[0].id == "ALT-ID"

    def test_field_timestamp(self):
        raw = _json_object(title="t", timestamp="2026-03-22T10:00:00Z")
        alert = self.norm.normalize(raw)[0]
        assert alert.timestamp is not None
        assert alert.timestamp.year == 2026

    def test_field_source_ip(self):
        raw = _json_object(title="t", source_ip="10.1.2.3")
        assert self.norm.normalize(raw)[0].source_ip == "10.1.2.3"

    def test_field_source_ip_alias_src_ip(self):
        raw = _json_object(title="t", src_ip="192.168.0.1")
        assert self.norm.normalize(raw)[0].source_ip == "192.168.0.1"

    def test_field_dest_ip(self):
        raw = _json_object(title="t", dest_ip="8.8.8.8")
        assert self.norm.normalize(raw)[0].dest_ip == "8.8.8.8"

    def test_field_dest_ip_alias_dst_ip(self):
        raw = _json_object(title="t", dst_ip="1.1.1.1")
        assert self.norm.normalize(raw)[0].dest_ip == "1.1.1.1"

    def test_field_user(self):
        raw = _json_object(title="t", user="jdoe")
        assert self.norm.normalize(raw)[0].user == "jdoe"

    def test_field_host(self):
        raw = _json_object(title="t", host="dc01.corp.local")
        assert self.norm.normalize(raw)[0].host == "dc01.corp.local"

    def test_field_category(self):
        raw = _json_object(title="t", category="Malware")
        assert self.norm.normalize(raw)[0].category == "Malware"

    def test_missing_fields_are_none(self):
        raw = _json_object(title="Minimal")
        alert = self.norm.normalize(raw)[0]
        assert alert.source_ip is None
        assert alert.dest_ip is None
        assert alert.user is None
        assert alert.host is None
        assert alert.category is None
        assert alert.timestamp is None

    def test_missing_id_generates_uuid(self):
        raw = _json_object(title="No ID")
        alert = self.norm.normalize(raw)[0]
        # UUID4 format: 8-4-4-4-12 hex chars with dashes
        assert len(alert.id) == 36
        assert alert.id.count("-") == 4


# ---------------------------------------------------------------------------
# GenericNormalizer — severity mapping (parametrize)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw_severity,expected", [
    ("critical",     AlertSeverity.CRITICAL),
    ("CRITICAL",     AlertSeverity.CRITICAL),
    ("informational", AlertSeverity.INFO),
    ("info",         AlertSeverity.INFO),
    ("low",          AlertSeverity.LOW),
    ("medium",       AlertSeverity.MEDIUM),
    ("moderate",     AlertSeverity.MEDIUM),
    ("high",         AlertSeverity.HIGH),
    ("emergency",    AlertSeverity.CRITICAL),
    ("fatal",        AlertSeverity.CRITICAL),
    ("1",            AlertSeverity.CRITICAL),
    ("2",            AlertSeverity.HIGH),
    ("3",            AlertSeverity.MEDIUM),
    ("4",            AlertSeverity.LOW),
    ("5",            AlertSeverity.INFO),
])
def test_generic_severity_string_aliases(raw_severity, expected):
    norm = GenericNormalizer()
    raw = _json_object(title="t", severity=raw_severity)
    assert norm.normalize(raw)[0].severity == expected


@pytest.mark.parametrize("raw_severity,expected", [
    (1, AlertSeverity.CRITICAL),
    (2, AlertSeverity.HIGH),
    (3, AlertSeverity.MEDIUM),
    (4, AlertSeverity.LOW),
    (5, AlertSeverity.INFO),
])
def test_generic_severity_integer(raw_severity, expected):
    norm = GenericNormalizer()
    raw = _json_object(title="t", severity=raw_severity)
    assert norm.normalize(raw)[0].severity == expected


def test_generic_severity_unknown_string_defaults_to_medium():
    norm = GenericNormalizer()
    raw = _json_object(title="t", severity="totally_unknown_level")
    assert norm.normalize(raw)[0].severity == AlertSeverity.MEDIUM


def test_generic_severity_missing_defaults_to_medium():
    norm = GenericNormalizer()
    raw = _json_object(title="t")
    assert norm.normalize(raw)[0].severity == AlertSeverity.MEDIUM


# ---------------------------------------------------------------------------
# SplunkNormalizer — can_handle
# ---------------------------------------------------------------------------


class TestSplunkNormalizerCanHandle:
    norm = SplunkNormalizer()

    def test_can_handle_results_key(self):
        assert self.norm.can_handle(json.dumps({"results": []}))

    def test_can_handle_results_key_with_extra_fields(self):
        assert self.norm.can_handle(json.dumps({"results": [], "preview": False, "messages": []}))

    def test_cannot_handle_plain_json_array(self):
        assert not self.norm.can_handle(json.dumps([{"title": "x"}]))

    def test_cannot_handle_json_object_without_results(self):
        assert not self.norm.can_handle(json.dumps({"title": "x", "severity": "high"}))

    def test_cannot_handle_garbage(self):
        assert not self.norm.can_handle("garbage input")


# ---------------------------------------------------------------------------
# SplunkNormalizer — normalize
# ---------------------------------------------------------------------------


class TestSplunkNormalizerNormalize:
    norm = SplunkNormalizer()

    def _wrap(self, *records: dict) -> str:
        return json.dumps({"results": list(records)})

    def test_empty_results_returns_empty_list(self):
        assert self.norm.normalize(json.dumps({"results": []})) == []

    def test_parses_results_key(self):
        raw = self._wrap(
            {"rule_name": "Brute Force", "urgency": "high"},
            {"rule_name": "Port Scan",   "urgency": "low"},
        )
        alerts = self.norm.normalize(raw)
        assert len(alerts) == 2

    def test_splunk_field_rule_name_maps_to_title(self):
        raw = self._wrap({"rule_name": "Credential Dump Detected", "urgency": "critical"})
        assert self.norm.normalize(raw)[0].title == "Credential Dump Detected"

    def test_splunk_field_urgency_maps_to_severity(self):
        raw = self._wrap({"rule_name": "t", "urgency": "high"})
        assert self.norm.normalize(raw)[0].severity == AlertSeverity.HIGH

    def test_splunk_field_time_maps_to_timestamp(self):
        raw = self._wrap({"rule_name": "t", "_time": "2026-03-22T10:00:00Z"})
        alert = self.norm.normalize(raw)[0]
        assert alert.timestamp is not None
        assert alert.timestamp.year == 2026

    def test_splunk_field_src_maps_to_source_ip(self):
        raw = self._wrap({"rule_name": "t", "src": "10.0.0.5"})
        assert self.norm.normalize(raw)[0].source_ip == "10.0.0.5"

    def test_splunk_field_dest_maps_to_dest_ip(self):
        raw = self._wrap({"rule_name": "t", "dest": "172.16.0.1"})
        assert self.norm.normalize(raw)[0].dest_ip == "172.16.0.1"

    def test_splunk_full_notable_event(self):
        raw = self._wrap({
            "event_id": "evt-001",
            "rule_name": "Phishing Detected",
            "urgency": "high",
            "_time": "2026-03-22T09:00:00Z",
            "src": "10.0.0.1",
            "dest": "185.220.101.47",
            "user": "jdoe",
            "host": "WORKSTATION01",
            "category": "Phishing",
        })
        alert = self.norm.normalize(raw)[0]
        assert alert.id == "evt-001"
        assert alert.title == "Phishing Detected"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.source_ip == "10.0.0.1"
        assert alert.dest_ip == "185.220.101.47"
        assert alert.user == "jdoe"
        assert alert.host == "WORKSTATION01"
        assert alert.category == "Phishing"

    @pytest.mark.parametrize("urgency,expected", [
        ("critical",     AlertSeverity.CRITICAL),
        ("high",         AlertSeverity.HIGH),
        ("medium",       AlertSeverity.MEDIUM),
        ("low",          AlertSeverity.LOW),
        ("informational", AlertSeverity.INFO),
    ])
    def test_splunk_urgency_severity_map(self, urgency, expected):
        raw = self._wrap({"rule_name": "t", "urgency": urgency})
        assert self.norm.normalize(raw)[0].severity == expected


# ---------------------------------------------------------------------------
# CSVNormalizer — can_handle
# ---------------------------------------------------------------------------


class TestCSVNormalizerCanHandle:
    norm = CSVNormalizer()

    def test_can_handle_csv_with_headers(self):
        assert self.norm.can_handle("title,severity,source_ip\nAlert 1,HIGH,10.0.0.1\n")

    def test_cannot_handle_json(self):
        assert not self.norm.can_handle(json.dumps([{"title": "x"}]))

    def test_cannot_handle_single_column(self):
        # Only 1 field → can_handle requires len(fieldnames) > 1
        assert not self.norm.can_handle("title\nAlert 1\n")

    def test_cannot_handle_empty_string(self):
        assert not self.norm.can_handle("")


# ---------------------------------------------------------------------------
# CSVNormalizer — normalize
# ---------------------------------------------------------------------------


class TestCSVNormalizerNormalize:
    norm = CSVNormalizer()

    _THREE_ROW_CSV = (
        "id,title,severity,source_ip,dest_ip,user,host,category\n"
        "1,Brute Force,HIGH,10.0.0.1,10.0.0.2,jdoe,ws01,Authentication\n"
        "2,Port Scan,LOW,10.0.0.3,10.0.0.4,,,Network\n"
        "3,Malware Alert,CRITICAL,10.0.0.5,,sysadmin,srv01,Malware\n"
    )

    def test_three_rows_return_three_alerts(self):
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert len(alerts) == 3
        assert all(isinstance(a, Alert) for a in alerts)

    def test_csv_field_title(self):
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert alerts[0].title == "Brute Force"

    def test_csv_field_severity(self):
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert alerts[0].severity == AlertSeverity.HIGH
        assert alerts[1].severity == AlertSeverity.LOW
        assert alerts[2].severity == AlertSeverity.CRITICAL

    def test_csv_field_source_ip(self):
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert alerts[0].source_ip == "10.0.0.1"

    def test_csv_field_dest_ip(self):
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert alerts[0].dest_ip == "10.0.0.2"

    def test_csv_field_user(self):
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert alerts[0].user == "jdoe"

    def test_csv_field_host(self):
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert alerts[0].host == "ws01"

    def test_csv_field_category(self):
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert alerts[0].category == "Authentication"

    def test_csv_missing_optional_columns_are_none(self):
        csv = "title,severity\nMinimal Alert,medium\n"
        alert = self.norm.normalize(csv)[0]
        assert alert.source_ip is None
        assert alert.dest_ip is None
        assert alert.user is None
        assert alert.host is None
        assert alert.category is None

    def test_csv_empty_optional_cell_is_none(self):
        # Row 2 has no user or host
        alerts = self.norm.normalize(self._THREE_ROW_CSV)
        assert alerts[1].user is None
        assert alerts[1].host is None

    def test_csv_case_insensitive_headers(self):
        csv = "TITLE,SEVERITY,SOURCE_IP\nTest Alert,critical,192.168.1.1\n"
        alert = self.norm.normalize(csv)[0]
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.source_ip == "192.168.1.1"

    def test_csv_empty_input_returns_empty_list(self):
        # Single-column or truly empty — either way normalize returns []
        assert self.norm.normalize("") == []

    def test_csv_headers_only_no_rows_returns_empty_list(self):
        csv = "title,severity,source_ip\n"
        alerts = self.norm.normalize(csv)
        assert alerts == []

    @pytest.mark.parametrize("severity_str,expected", [
        ("critical",     AlertSeverity.CRITICAL),
        ("high",         AlertSeverity.HIGH),
        ("medium",       AlertSeverity.MEDIUM),
        ("low",          AlertSeverity.LOW),
        ("informational", AlertSeverity.INFO),
        ("unknown_level", AlertSeverity.MEDIUM),
    ])
    def test_csv_severity_values(self, severity_str, expected):
        csv = f"title,severity\nAlert,{severity_str}\n"
        assert self.norm.normalize(csv)[0].severity == expected
