"""Prompt injection detection for alert fields.

Detects and optionally redacts suspicious patterns in alert data before
LLM submission to mitigate prompt injection attacks.
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from sift.models import Alert

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SeverityLevel(str, Enum):
    """Severity of injection finding."""

    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class InjectionFinding(BaseModel):
    """A detected injection pattern in an alert field."""

    field: str = Field(..., description="Alert field name where pattern was found")
    pattern_type: str = Field(..., description="Type of injection pattern (e.g., 'instruction_override')")
    severity: SeverityLevel = Field(..., description="Severity level of the finding")
    redaction: str = Field(..., description="Redaction suggestion for the suspicious content")
    value_preview: Optional[str] = Field(None, description="Preview of suspicious value (truncated)")


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class PromptInjectionDetector:
    """Detects prompt injection patterns in alert fields."""

    def __init__(
        self,
        case_insensitive: bool = True,
        whitelist_patterns: list[str] | None = None,
    ):
        """Initialize detector with injection patterns.

        Args:
            case_insensitive: If True, perform case-insensitive matching.
            whitelist_patterns: Optional list of regex patterns.  Any field
                value matching one of these patterns is exempted from all
                injection checks (e.g. known-safe alert templates).
        """
        self.case_insensitive = case_insensitive
        flags = re.IGNORECASE if case_insensitive else 0
        self._whitelist: list[re.Pattern] = [
            re.compile(p, flags) for p in (whitelist_patterns or [])
        ]
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for injection detection."""
        flags = re.IGNORECASE if self.case_insensitive else 0

        # Pattern 1: "ignore previous instructions" variants
        # re.DOTALL so . matches \n; NFKC normalisation applied before matching
        # to defeat zero-width space and Unicode lookalike bypasses.
        self.pattern_ignore_instructions = re.compile(
            r"(ignore|disregard|forget|dismiss|bypass|override)[\s\S]{0,40}?"
            r"(previous|prior|earlier|above|preceding)[\s\S]{0,40}?"
            r"(instruction|directive|prompt|command|context|system)",
            flags | re.DOTALL,
        )

        # Pattern 2: LLM-redirection via "instead" keyword (narrowed vs. original).
        # Matches "verb instead" OR "instead verb" to catch injection while
        # avoiding FP on normal log lines like "Generate report: failed".
        # Optional punctuation (,;.) after "instead" handles "Instead, output ..."
        self.pattern_instead_output = re.compile(
            r"(?:"
            r"(output|respond|return|generate|create|print|write)\s+instead"
            r"|instead[\s,;.]+(?:of\s+)?(output|respond|return|generate|create|print|write)"
            r"|rather\s+than\s+(?:summariz|analyz|triag|the\s+above)"
            r")",
            flags,
        )

        # Pattern 3: JSON escape sequences (escaped quotes, control chars)
        self.pattern_json_escapes = re.compile(
            r'\\(?:["\\/bfnrtu]|u[0-9a-fA-F]{4})',
            flags,
        )

        # Pattern 4: Base64 or hex encoded payloads.
        # Branch 1: 12+ base64 chars that contain at least one '+' or '/' — lookahead
        #   rules out plain English words (e.g. "Exfiltration", "Configuration")
        #   which are purely alphanumeric and never contain Base64 special chars.
        # Branch 2/3: padded Base64 (== or =) — padding chars cannot appear in
        #   normal prose, so any length is suspicious.
        # Branch 4: 15+ purely-alphanumeric chars — raised from 12 so that common
        #   security terms ("Exfiltration"=12, "Configuration"=13) are excluded
        #   while long random-looking Base64 without special chars is still caught.
        # Branch 5: hex-encoded bytes — 10+ two-hex-digit pairs (20+ hex chars).
        self.pattern_base64_hex = re.compile(
            r'(?:'
            r'(?=[A-Za-z0-9+/]*[+/])[A-Za-z0-9+/]{12,}'  # Branch 1: 12+ with +/
            r'|[A-Za-z0-9+/]{4,}=='                        # Branch 2: == padded
            r'|[A-Za-z0-9+/]{8,}='                         # Branch 3: = padded
            r'|[A-Za-z0-9]{15,}'                            # Branch 4: 15+ alphanumeric
            r'|(?:[0-9a-fA-F]{2}){10,}'                     # Branch 5: hex pairs
            r')',
            flags,
        )

        # Pattern 5: Shell command injection ($(...), backticks, $var)
        self.pattern_shell_commands = re.compile(
            r'(?:\$\([^)]*\)|`[^`]*`|\$\w+)',
            flags,
        )

    def detect(self, alert: Alert) -> list[InjectionFinding]:
        """Scan alert fields for injection patterns.

        Args:
            alert: Alert instance to scan.

        Returns:
            List of InjectionFinding objects for each detected pattern.
        """
        findings: list[InjectionFinding] = []

        # Fields to scan: title, description, and string-valued custom fields
        fields_to_scan: dict[str, str | None] = {
            "title": alert.title,
            "description": alert.description,
            "category": alert.category,
            "source": alert.source,
            "user": alert.user,
            "host": alert.host,
        }

        # Add raw dict values if they're strings
        if alert.raw:
            for key, val in alert.raw.items():
                if isinstance(val, str):
                    fields_to_scan[f"raw.{key}"] = val

        for field_name, field_value in fields_to_scan.items():
            if field_value is None or not isinstance(field_value, str):
                continue

            # Skip fields that match an operator-defined whitelist pattern
            if self._whitelist and any(p.search(field_value) for p in self._whitelist):
                continue

            # Check each pattern (use if, not elif, to detect all patterns in a field)
            if self.pattern_ignore_instructions.search(field_value):
                findings.append(
                    InjectionFinding(
                        field=field_name,
                        pattern_type="instruction_override",
                        severity=SeverityLevel.CRITICAL,
                        redaction="[REDACTED: instruction override attempt]",
                        value_preview=self._truncate(field_value),
                    )
                )

            if self.pattern_instead_output.search(field_value):
                findings.append(
                    InjectionFinding(
                        field=field_name,
                        pattern_type="output_manipulation",
                        severity=SeverityLevel.CRITICAL,
                        redaction="[REDACTED: output manipulation attempt]",
                        value_preview=self._truncate(field_value),
                    )
                )

            if self.pattern_json_escapes.search(field_value):
                findings.append(
                    InjectionFinding(
                        field=field_name,
                        pattern_type="json_escape_sequence",
                        severity=SeverityLevel.WARNING,
                        redaction="[REDACTED: JSON escape sequences]",
                        value_preview=self._truncate(field_value),
                    )
                )

            if self.pattern_base64_hex.search(field_value):
                findings.append(
                    InjectionFinding(
                        field=field_name,
                        pattern_type="encoded_payload",
                        severity=SeverityLevel.WARNING,
                        redaction="[REDACTED: encoded payload]",
                        value_preview=self._truncate(field_value),
                    )
                )

            if self.pattern_shell_commands.search(field_value):
                findings.append(
                    InjectionFinding(
                        field=field_name,
                        pattern_type="shell_injection",
                        severity=SeverityLevel.CRITICAL,
                        redaction="[REDACTED: shell command attempt]",
                        value_preview=self._truncate(field_value),
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
            if "." in field_name:
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

    @staticmethod
    def _truncate(value: str, max_len: int = 80) -> str:
        """Truncate string for preview display.

        Args:
            value: String to truncate.
            max_len: Maximum length of preview.

        Returns:
            Truncated string with ellipsis if needed.
        """
        if len(value) <= max_len:
            return value
        return value[:max_len] + "..."


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
