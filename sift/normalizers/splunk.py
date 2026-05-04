"""Splunk JSON export normalizer.

Handles the standard Splunk search results JSON format:
  {"results": [ {...}, {...} ], "preview": false, ... }

Also handles Splunk Notable Events (ES) with specific field names.
"""

from __future__ import annotations

import json
import uuid

from ..models import Alert, AlertSeverity
from .generic import _parse_severity, _parse_timestamp

# Splunk Common Information Model (CIM) field names
_SPLUNK_SEVERITY_MAP = {
    "unknown": AlertSeverity.INFO,
    "informational": AlertSeverity.INFO,
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
}

# Splunk ES urgency field
_URGENCY_MAP = {
    "informational": AlertSeverity.INFO,
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
}


def _splunk_record_to_alert(record: dict) -> Alert:
    # Splunk ES notable event fields take priority
    alert_id = (
        record.get("event_id")
        or record.get("orig_event_id")
        or record.get("_cd")
        or str(uuid.uuid4())
    )

    # Title: rule_name > rule_title > search_name > source
    title = (
        record.get("rule_name")
        or record.get("rule_title")
        or record.get("search_name")
        or record.get("source")
        or "Splunk Alert"
    )

    # Severity: urgency (ES) > severity > info.severity > default
    sev_raw = record.get("urgency") or record.get("severity") or record.get("info.severity")
    if isinstance(sev_raw, str) and sev_raw.lower() in _URGENCY_MAP:
        severity = _URGENCY_MAP[sev_raw.lower()]
    else:
        severity = _parse_severity(sev_raw)

    # Timestamp: _time > timestamp
    ts_raw = record.get("_time") or record.get("timestamp") or record.get("event_time")
    timestamp = _parse_timestamp(ts_raw)

    return Alert(
        id=str(alert_id),
        timestamp=timestamp,
        severity=severity,
        title=str(title),
        description=record.get("description") or record.get("rule_description") or record.get("_raw"),
        source=record.get("source") or record.get("sourcetype"),
        source_ip=record.get("src") or record.get("src_ip") or record.get("source_ip"),
        dest_ip=record.get("dest") or record.get("dest_ip") or record.get("destination_ip"),
        user=record.get("user") or record.get("src_user"),
        host=record.get("host") or record.get("dest_host"),
        category=record.get("category") or record.get("type") or record.get("tag"),
        raw=record,
    )


def _parse_ndjson(raw: str) -> list[dict]:
    """Parse newline-delimited JSON; return only dict lines."""
    records: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except Exception:
            pass
    return records


class SplunkNormalizer:
    """Normalizer for Splunk JSON export format."""

    @property
    def name(self) -> str:
        return "splunk"

    def can_handle(self, raw: str) -> bool:
        stripped = raw.strip()
        # Standard Splunk export: {"results": [...]}
        try:
            data = json.loads(stripped)
            if isinstance(data, dict) and "results" in data:
                return True
        except Exception:
            pass
        # Splunk ndjson export: one JSON object per line
        records = _parse_ndjson(stripped)
        return len(records) > 0 and any(
            "_time" in r or "urgency" in r or "rule_name" in r or "event_id" in r
            for r in records
        )

    def normalize(self, raw: str) -> list[Alert]:
        stripped = raw.strip()
        # Try standard {"results": [...]} first
        try:
            data = json.loads(stripped)
            if isinstance(data, dict) and "results" in data:
                return [_splunk_record_to_alert(r) for r in data.get("results", []) if isinstance(r, dict)]
        except Exception:
            pass
        # Fall back to ndjson
        records = _parse_ndjson(stripped)
        return [_splunk_record_to_alert(r) for r in records]
