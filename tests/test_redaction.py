"""Tests for Alert.redact() and AlertRedactionConfig."""

from __future__ import annotations

import pytest

from sift.config import AlertRedactionConfig, AppConfig
from sift.models import Alert, AlertSeverity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(**kwargs) -> Alert:
    defaults = dict(
        id="test-1",
        title="Suspicious login",
        description="Multiple failed attempts",
        source_ip="10.0.0.1",
        dest_ip="192.168.1.5",
        user="alice",
        host="workstation-01",
        iocs=["10.0.0.1", "evil.com"],
        raw={"original": "data", "score": 99},
        severity=AlertSeverity.HIGH,
    )
    defaults.update(kwargs)
    return Alert(**defaults)


# ---------------------------------------------------------------------------
# String field redaction
# ---------------------------------------------------------------------------

class TestStringFieldRedaction:
    def test_redact_title(self):
        alert = _make_alert()
        redacted = alert.redact(["title"])
        assert redacted.title == "[REDACTED]"

    def test_redact_description(self):
        alert = _make_alert()
        redacted = alert.redact(["description"])
        assert redacted.description == "[REDACTED]"

    def test_redact_source_ip(self):
        alert = _make_alert()
        redacted = alert.redact(["source_ip"])
        assert redacted.source_ip == "[REDACTED]"

    def test_redact_dest_ip(self):
        alert = _make_alert()
        redacted = alert.redact(["dest_ip"])
        assert redacted.dest_ip == "[REDACTED]"

    def test_redact_user(self):
        alert = _make_alert()
        redacted = alert.redact(["user"])
        assert redacted.user == "[REDACTED]"

    def test_redact_host(self):
        alert = _make_alert()
        redacted = alert.redact(["host"])
        assert redacted.host == "[REDACTED]"


# ---------------------------------------------------------------------------
# Special-type field redaction
# ---------------------------------------------------------------------------

class TestSpecialFieldRedaction:
    def test_redact_iocs_returns_empty_list(self):
        alert = _make_alert()
        redacted = alert.redact(["iocs"])
        assert redacted.iocs == []

    def test_redact_raw_returns_empty_dict(self):
        alert = _make_alert()
        redacted = alert.redact(["raw"])
        assert redacted.raw == {}


# ---------------------------------------------------------------------------
# Multiple fields
# ---------------------------------------------------------------------------

class TestMultipleFieldRedaction:
    def test_redact_multiple_fields(self):
        alert = _make_alert()
        redacted = alert.redact(["user", "host", "source_ip", "iocs", "raw"])
        assert redacted.user == "[REDACTED]"
        assert redacted.host == "[REDACTED]"
        assert redacted.source_ip == "[REDACTED]"
        assert redacted.iocs == []
        assert redacted.raw == {}
        # Unredacted fields remain intact
        assert redacted.title == alert.title
        assert redacted.dest_ip == alert.dest_ip

    def test_redact_empty_list_is_noop(self):
        alert = _make_alert()
        redacted = alert.redact([])
        assert redacted.title == alert.title
        assert redacted.user == alert.user


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestRedactionErrors:
    def test_unknown_field_raises_value_error(self):
        alert = _make_alert()
        with pytest.raises(ValueError, match="Unknown redaction field"):
            alert.redact(["nonexistent_field"])

    def test_error_message_lists_valid_fields(self):
        alert = _make_alert()
        with pytest.raises(ValueError, match="title"):
            alert.redact(["bad_field"])


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------

class TestRedactionImmutability:
    def test_redact_returns_copy_not_original(self):
        alert = _make_alert()
        redacted = alert.redact(["title", "user", "iocs", "raw"])
        # Original must not be mutated
        assert alert.title == "Suspicious login"
        assert alert.user == "alice"
        assert alert.iocs == ["10.0.0.1", "evil.com"]
        assert alert.raw == {"original": "data", "score": 99}
        # Redacted copy has new values
        assert redacted.title == "[REDACTED]"
        assert redacted.user == "[REDACTED]"
        assert redacted.iocs == []
        assert redacted.raw == {}


# ---------------------------------------------------------------------------
# AlertRedactionConfig
# ---------------------------------------------------------------------------

class TestAlertRedactionConfig:
    def test_defaults(self):
        cfg = AlertRedactionConfig()
        assert cfg.fields == []
        assert cfg.redact_raw is False

    def test_custom_fields(self):
        cfg = AlertRedactionConfig(fields=["user", "host"], redact_raw=True)
        assert cfg.fields == ["user", "host"]
        assert cfg.redact_raw is True

    def test_app_config_has_redaction_field(self):
        app_cfg = AppConfig()
        assert hasattr(app_cfg, "redaction")
        assert isinstance(app_cfg.redaction, AlertRedactionConfig)
        assert app_cfg.redaction.fields == []
        assert app_cfg.redaction.redact_raw is False
