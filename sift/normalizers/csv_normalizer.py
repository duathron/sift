"""CSV alert normalizer.

Reads a CSV with headers. Column mapping uses the same alias lists
as the generic normalizer — common SIEM export column names are recognized
automatically.
"""

from __future__ import annotations

import csv
import io
import uuid

from ..models import Alert
from .generic import (
    _CATEGORY_FIELDS,
    _DESC_FIELDS,
    _DEST_IP_FIELDS,
    _HOST_FIELDS,
    _ID_FIELDS,
    _SEVERITY_FIELDS,
    _SOURCE_FIELDS,
    _SOURCE_IP_FIELDS,
    _TIMESTAMP_FIELDS,
    _TITLE_FIELDS,
    _USER_FIELDS,
    _first,
    _parse_severity,
    _parse_timestamp,
)


def _row_to_alert(row: dict) -> Alert:
    # Lower-case all keys for case-insensitive lookup
    record = {k.lower().strip(): v for k, v in row.items()}

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
        raw=dict(row),
    )


class CSVNormalizer:
    """Normalizer for CSV alert exports."""

    @property
    def name(self) -> str:
        return "csv"

    def can_handle(self, raw: str) -> bool:
        try:
            reader = csv.DictReader(io.StringIO(raw.strip()))
            return reader.fieldnames is not None and len(reader.fieldnames) > 1
        except Exception:
            return False

    def normalize(self, raw: str) -> list[Alert]:
        try:
            reader = csv.DictReader(io.StringIO(raw.strip()))
            return [_row_to_alert(row) for row in reader]
        except Exception:
            return []
