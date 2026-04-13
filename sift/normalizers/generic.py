"""Generic JSON normalizer — handles arbitrary alert JSON.

Expects a JSON object or array. Field mapping is best-effort:
common field names are tried in order; unknown fields go into Alert.raw.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from ..models import Alert, AlertSeverity

# Field name aliases tried in order (first match wins)
_ID_FIELDS = ["id", "alert_id", "event_id", "uid", "_id"]
_TIMESTAMP_FIELDS = ["timestamp", "time", "event_time", "created_at", "@timestamp", "date"]
_SEVERITY_FIELDS = ["severity", "priority", "level", "risk_level", "alert_level"]
_TITLE_FIELDS = ["title", "name", "alert_name", "message", "msg", "description", "event_name", "label"]
_DESC_FIELDS = ["description", "details", "message", "msg", "summary"]
_SOURCE_FIELDS = ["source", "sensor", "detector", "product", "vendor"]
_SOURCE_IP_FIELDS = ["source_ip", "src_ip", "src", "sourceAddress", "source_address", "attacker_ip", "source ip", "src ip"]
_DEST_IP_FIELDS = ["dest_ip", "dst_ip", "dst", "destAddress", "destination_ip", "target_ip", "destination ip", "dest ip", "dst ip"]
_USER_FIELDS = ["user", "username", "user_name", "account", "actor"]
_HOST_FIELDS = ["host", "hostname", "computer", "device", "endpoint", "machine"]
_CATEGORY_FIELDS = ["category", "type", "alert_type", "event_type", "classification", "label"]

_SEVERITY_MAP = {
    "info": AlertSeverity.INFO,
    "informational": AlertSeverity.INFO,
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "moderate": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
    "emergency": AlertSeverity.CRITICAL,
    "fatal": AlertSeverity.CRITICAL,
    "1": AlertSeverity.CRITICAL,
    "2": AlertSeverity.HIGH,
    "3": AlertSeverity.MEDIUM,
    "4": AlertSeverity.LOW,
    "5": AlertSeverity.INFO,
}


def _first(record: dict, keys: list[str]) -> Any:
    for k in keys:
        if k in record:
            return record[k]
    return None


def _parse_severity(value: Any) -> AlertSeverity:
    if isinstance(value, int):
        value = str(value)
    if isinstance(value, str):
        return _SEVERITY_MAP.get(value.lower().strip(), AlertSeverity.MEDIUM)
    return AlertSeverity.MEDIUM


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            from datetime import datetime as dt
            return dt.fromisoformat(value)
        except Exception:
            return None
    return None


def _record_to_alert(record: dict) -> Alert:
    alert_id = str(_first(record, _ID_FIELDS) or uuid.uuid4())
    title = str(_first(record, _TITLE_FIELDS) or "Unknown Alert")
    desc_raw = _first(record, _DESC_FIELDS)
    description = str(desc_raw) if desc_raw and str(desc_raw) != title else None

    return Alert(
        id=alert_id,
        timestamp=_parse_timestamp(_first(record, _TIMESTAMP_FIELDS)),
        severity=_parse_severity(_first(record, _SEVERITY_FIELDS)),
        title=title,
        description=description,
        source=str(v) if (v := _first(record, _SOURCE_FIELDS)) else None,
        source_ip=str(v) if (v := _first(record, _SOURCE_IP_FIELDS)) else None,
        dest_ip=str(v) if (v := _first(record, _DEST_IP_FIELDS)) else None,
        user=str(v) if (v := _first(record, _USER_FIELDS)) else None,
        host=str(v) if (v := _first(record, _HOST_FIELDS)) else None,
        category=str(v) if (v := _first(record, _CATEGORY_FIELDS)) else None,
        raw=record,
    )


class GenericNormalizer:
    """Normalizer for generic JSON alert format."""

    @property
    def name(self) -> str:
        return "generic"

    def can_handle(self, raw: str) -> bool:
        try:
            data = json.loads(raw.strip())
            return isinstance(data, (dict, list))
        except Exception:
            return False

    def normalize(self, raw: str) -> list[Alert]:
        try:
            data = json.loads(raw.strip())
            records: list[dict] = data if isinstance(data, list) else [data]
            return [_record_to_alert(r) for r in records if isinstance(r, dict)]
        except Exception:
            return []
