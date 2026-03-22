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
        description=record.get("description") or record.get("rule_description"),
        source=record.get("source") or record.get("sourcetype"),
        source_ip=record.get("src") or record.get("src_ip") or record.get("source_ip"),
        dest_ip=record.get("dest") or record.get("dest_ip") or record.get("destination_ip"),
        user=record.get("user") or record.get("src_user"),
        host=record.get("host") or record.get("dest_host"),
        category=record.get("category") or record.get("type") or record.get("tag"),
        raw=record,
    )


class SplunkNormalizer:
    """Normalizer for Splunk JSON export format."""

    @property
    def name(self) -> str:
        return "splunk"

    def can_handle(self, raw: str) -> bool:
        try:
            data = json.loads(raw.strip())
            # Splunk search results have a "results" key
            return isinstance(data, dict) and "results" in data
        except Exception:
            return False

    def normalize(self, raw: str) -> list[Alert]:
        try:
            data = json.loads(raw.strip())
            results = data.get("results", [])
            return [_splunk_record_to_alert(r) for r in results if isinstance(r, dict)]
        except Exception:
            return []
