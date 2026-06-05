"""Prompt injection detection for alert fields.

Detects and optionally redacts suspicious patterns in alert data before
LLM submission to mitigate prompt injection attacks.

The pattern-matching engine (all 7 patterns, NFKC normalisation, and
whitelist handling) is provided by ``shipwright_kit.security.injection``.
This module supplies sift's Alert-shaped field extraction and redaction.
"""

from __future__ import annotations

import logging
from typing import Optional

from shipwright_kit.security.injection import (
    InjectionFinding,
    SeverityLevel,
)
from shipwright_kit.security.injection import (
    PromptInjectionDetector as _CoreDetector,
)

from sift.models import Alert

logger = logging.getLogger(__name__)

__all__ = ["InjectionFinding", "PromptInjectionDetector", "SeverityLevel", "redact_alerts", "scan_alert"]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class PromptInjectionDetector:
    """Scans Alert fields using the shared shipwright_kit injection engine."""

    def __init__(
        self,
        case_insensitive: bool = True,
        whitelist_patterns: list[str] | None = None,
    ) -> None:
        self._core = _CoreDetector(
            case_insensitive=case_insensitive,
            whitelist_patterns=whitelist_patterns,
        )

    def detect(self, alert: Alert) -> list[InjectionFinding]:
        fields_to_scan: dict[str, str | None] = {
            "title": alert.title,
            "description": alert.description,
            "category": alert.category,
            "source": alert.source,
            "user": alert.user,
            "host": alert.host,
        }
        if alert.raw:
            for key, val in alert.raw.items():
                if isinstance(val, str):
                    fields_to_scan[f"raw.{key}"] = val
        for i, ioc_val in enumerate(alert.iocs):
            fields_to_scan[f"ioc.{i}"] = ioc_val

        findings: list[InjectionFinding] = []
        for field_name, field_value in fields_to_scan.items():
            if field_value is None or not isinstance(field_value, str):
                continue
            findings.extend(
                self._core.detect(
                    field_value,
                    field_name=field_name,
                    is_ioc_field=field_name.startswith("ioc."),
                )
            )
        return findings

    def redact_alert(self, alert: Alert, findings: list[InjectionFinding]) -> Alert:
        """Redact suspicious fields in alert based on findings.

        Creates a modified copy of the alert with suspicious field values
        replaced by redaction suggestions.

        Args:
            alert: Original alert instance.
            findings: List of injection findings to apply.

        Returns:
            New Alert instance with redacted fields.
        """
        if not findings:
            return alert

        # Build set of fields to redact
        fields_to_redact = {f.field for f in findings}

        # Create updated alert with redacted values
        alert_dict = alert.model_dump()

        for field_name in fields_to_redact:
            if field_name.startswith("ioc."):
                # Handle IOC list entries
                try:
                    idx = int(field_name[4:])
                    iocs_list = alert_dict.get("iocs", [])
                    if 0 <= idx < len(iocs_list):
                        iocs_list[idx] = "[REDACTED]"
                except (ValueError, TypeError):
                    pass
            elif "." in field_name:
                # Handle nested raw.* fields
                parts = field_name.split(".", 1)
                if parts[0] == "raw" and len(parts) == 2:
                    if alert_dict.get("raw"):
                        alert_dict["raw"][parts[1]] = "[REDACTED]"
            else:
                # Handle top-level fields
                if field_name in alert_dict:
                    alert_dict[field_name] = "[REDACTED]"

        return Alert(**alert_dict)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def scan_alert(alert: Alert) -> list[InjectionFinding]:
    """Scan a single alert for injection patterns.

    Args:
        alert: Alert to scan.

    Returns:
        List of injection findings.
    """
    detector = PromptInjectionDetector()
    return detector.detect(alert)


def redact_alerts(alerts: list[Alert], detector: Optional[PromptInjectionDetector] = None) -> list[Alert]:
    """Scan and redact a list of alerts.

    Args:
        alerts: Alerts to process.
        detector: Optional detector instance (creates new if None).

    Returns:
        List of potentially redacted alerts.
    """
    if detector is None:
        detector = PromptInjectionDetector()

    redacted = []
    for alert in alerts:
        findings = detector.detect(alert)
        if findings:
            logger.warning(
                f"Found {len(findings)} injection pattern(s) in alert {alert.id}: "
                f"{', '.join(f.pattern_type for f in findings)}"
            )
            redacted.append(detector.redact_alert(alert, findings))
        else:
            redacted.append(alert)

    return redacted
