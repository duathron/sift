"""Programmatic alert generator for sift tests."""

import random
import uuid
from datetime import datetime, timezone
from typing import Any

from sift.models import Alert, AlertSeverity


# ---------------------------------------------------------------------------
# AlertBuilder — fluent interface
# ---------------------------------------------------------------------------


class AlertBuilder:
    """Fluent builder for constructing Alert instances in tests.

    Usage::

        alert = (
            AlertBuilder()
            .severity("HIGH")
            .title("Test Alert")
            .source_ip("10.0.0.1")
            .with_iocs(["185.220.101.47", "evil.phish.ru"])
            .build()
        )
    """

    def __init__(self) -> None:
        self._id: str | None = None
        self._timestamp: datetime | None = None
        self._severity: AlertSeverity = AlertSeverity.MEDIUM
        self._title: str = "Test Alert"
        self._description: str = "Auto-generated test alert."
        self._source: str = "test-sensor"
        self._source_ip: str | None = None
        self._dest_ip: str | None = None
        self._user: str | None = None
        self._host: str | None = None
        self._category: str = "Test"
        self._iocs: list[str] = []
        self._technique_ids: list[str] = []
        self._raw: dict[str, Any] = {}

    # --- identity ---

    def id(self, value: str) -> "AlertBuilder":
        self._id = value
        return self

    def timestamp(self, value: datetime) -> "AlertBuilder":
        self._timestamp = value
        return self

    # --- severity / classification ---

    def severity(self, value: str | AlertSeverity) -> "AlertBuilder":
        self._severity = AlertSeverity(value) if isinstance(value, str) else value
        return self

    def category(self, value: str) -> "AlertBuilder":
        self._category = value
        return self

    # --- descriptive ---

    def title(self, value: str) -> "AlertBuilder":
        self._title = value
        return self

    def description(self, value: str) -> "AlertBuilder":
        self._description = value
        return self

    def source(self, value: str) -> "AlertBuilder":
        self._source = value
        return self

    # --- network context ---

    def source_ip(self, value: str) -> "AlertBuilder":
        self._source_ip = value
        return self

    def dest_ip(self, value: str) -> "AlertBuilder":
        self._dest_ip = value
        return self

    def user(self, value: str) -> "AlertBuilder":
        self._user = value
        return self

    def host(self, value: str) -> "AlertBuilder":
        self._host = value
        return self

    # --- enrichment ---

    def with_iocs(self, iocs: list[str]) -> "AlertBuilder":
        self._iocs = list(iocs)
        return self

    def with_techniques(self, technique_ids: list[str]) -> "AlertBuilder":
        self._technique_ids = list(technique_ids)
        return self

    def with_raw(self, raw: dict[str, Any]) -> "AlertBuilder":
        self._raw = dict(raw)
        return self

    # --- terminal ---

    def build(self) -> Alert:
        """Construct and return the Alert instance."""
        return Alert(
            id=self._id or str(uuid.uuid4()),
            timestamp=self._timestamp or datetime.now(tz=timezone.utc),
            severity=self._severity,
            title=self._title,
            description=self._description,
            source=self._source,
            source_ip=self._source_ip,
            dest_ip=self._dest_ip,
            user=self._user,
            host=self._host,
            category=self._category,
            iocs=self._iocs,
            technique_ids=self._technique_ids,
            raw=self._raw,
        )


# ---------------------------------------------------------------------------
# Batch generators
# ---------------------------------------------------------------------------

_PHISHING_TITLES = [
    "Phishing Email Detected",
    "Suspicious URL Clicked",
    "DNS Query to Phishing Domain",
    "Credential Theft Attempt",
]

_PHISHING_SEVERITIES = [AlertSeverity.HIGH, AlertSeverity.CRITICAL]
_PHISHING_SOURCE_POOL = ["10.0.0.11", "10.0.0.12", "10.0.0.13"]
_PHISHING_SHARED_IOC = "185.220.101.47"

_NOISE_TITLES = [
    "Port Scan Detected",
    "Failed SSH Login",
    "DHCP Lease Renewed",
    "Scheduled Task Created",
]

_NOISE_SEVERITIES = [AlertSeverity.INFO, AlertSeverity.LOW]


def _random_internal_ip() -> str:
    return f"10.{random.randint(0, 5)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_external_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def make_phishing_batch(count: int = 10) -> list[Alert]:
    """Generate *count* alerts with phishing characteristics.

    All alerts share the IOC ``185.220.101.47`` and are HIGH or CRITICAL
    severity.  source_ip is drawn from a small internal pool to simulate
    multiple affected hosts.
    """
    alerts: list[Alert] = []
    for _ in range(count):
        alert = (
            AlertBuilder()
            .severity(random.choice(_PHISHING_SEVERITIES))
            .title(random.choice(_PHISHING_TITLES))
            .description("Phishing activity detected on the network.")
            .source("email-gateway")
            .source_ip(random.choice(_PHISHING_SOURCE_POOL))
            .dest_ip(_PHISHING_SHARED_IOC)
            .category("Phishing")
            .with_iocs([_PHISHING_SHARED_IOC, "evil.phish.ru"])
            .with_techniques(["T1566.002"])
            .with_raw({"campaign": "test-phish-batch"})
            .build()
        )
        alerts.append(alert)
    return alerts


def make_noise_batch(count: int = 15) -> list[Alert]:
    """Generate *count* low-severity noise alerts.

    Severities are INFO or LOW.  IPs are randomised to avoid artificial
    clustering on network fields.
    """
    alerts: list[Alert] = []
    for _ in range(count):
        alert = (
            AlertBuilder()
            .severity(random.choice(_NOISE_SEVERITIES))
            .title(random.choice(_NOISE_TITLES))
            .description("Routine or low-confidence event.")
            .source("siem-rule")
            .source_ip(_random_internal_ip())
            .dest_ip(_random_external_ip())
            .category("Noise")
            .with_iocs([])
            .with_techniques([])
            .with_raw({"generated": True})
            .build()
        )
        alerts.append(alert)
    return alerts


def make_mixed_batch(critical_count: int = 3, noise_count: int = 12) -> list[Alert]:
    """Return a shuffled mix of phishing and noise alerts.

    Produces ``critical_count`` phishing alerts combined with
    ``noise_count`` noise alerts, then shuffled to simulate a realistic
    unsorted alert feed.
    """
    alerts = make_phishing_batch(critical_count) + make_noise_batch(noise_count)
    random.shuffle(alerts)
    return alerts
