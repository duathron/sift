"""Phase 1: Redaction value-level leak tests — TDD RED first.

Covers three leak channels identified in 2026-06-12-redaction-value-level.md:

  Channel 1: alert.raw serialized verbatim into JSON/HTML/MD/STIX output
  Channel 2: raw dict re-extracted into iocs/iocs_typed by _collect_text_fields
  Channel 3: named-field value re-extracted as IOC (even after field is blanked)

Also covers:
  - All-formats absence scan (parametrized)
  - raw=={} suppression when redaction active; explicit override keeps raw
  - IOC-count-decrease when redaction active
  - Channel 3 known residual: value in non-redacted description text is NOT removed
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from sift.models import IOC, Alert, AlertSeverity, Cluster, ClusterPriority, TriageReport
from sift.output.export import export_json
from sift.output.html import render_html_report
from sift.output.md import render_md_report
from sift.output.stix import STIXExporter
from sift.pipeline.ioc_extractor import enrich_alert_iocs

# ---------------------------------------------------------------------------
# Sensitive value used across all tests
# ---------------------------------------------------------------------------

_SENSITIVE_IP = "10.0.0.99"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_leaky_alert(**kwargs) -> Alert:
    """Alert where _SENSITIVE_IP appears in source_ip, raw["message"], and raw["evt"]["src"]."""
    defaults = dict(
        id=str(uuid.uuid4()),
        title="Port scan detected",
        description="Scan activity from internal host",
        source_ip=_SENSITIVE_IP,
        severity=AlertSeverity.HIGH,
        raw={
            "message": f"Connection attempt from {_SENSITIVE_IP}",
            "evt": {"src": _SENSITIVE_IP, "dst": "192.168.1.1"},
            "score": 42,
        },
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def _make_report(alert: Alert) -> TriageReport:
    cluster = Cluster(
        id=str(uuid.uuid4()),
        label="Port Scan Cluster",
        alerts=[alert],
        priority=ClusterPriority.HIGH,
        score=10.0,
        iocs=alert.iocs,
        iocs_typed=alert.iocs_typed,
    )
    return TriageReport(
        alerts_ingested=1,
        alerts_after_dedup=1,
        clusters=[cluster],
        analyzed_at=datetime.now(timezone.utc),
    )


def _full_pipeline(alert: Alert, fields: list[str]) -> tuple[Alert, set[str]]:
    """Run Channel 1+2+3 fix: returns (enriched_alert, redacted_values).

    Uses the Phase 1 pipeline helper from sift.pipeline.redaction.
    """
    from sift.pipeline.redaction import apply_redact_and_enrich, get_redacted_values

    redacted_values = get_redacted_values(alert, fields)
    enriched = apply_redact_and_enrich(alert, fields)
    return enriched, redacted_values


# ===========================================================================
# Section 1 — Channel 1: raw dict must be suppressed in output when redaction active
# ===========================================================================


class TestChannel1RawSuppression:
    """raw must be {} in the output alert when redaction is active."""

    def test_raw_suppressed_in_json_when_redaction_active(self):
        """Channel 1: export_json must not contain _SENSITIVE_IP in raw dict."""
        alert = _make_leaky_alert()
        # Channel 1+2 fix: suppress raw before enrichment
        redacted = alert.redact(["source_ip"])
        suppressed = redacted.model_copy(update={"raw": {}})
        enriched = enrich_alert_iocs(suppressed)
        report = _make_report(enriched)

        output = export_json(report)
        data = json.loads(output)
        alert_data = data["clusters"][0]["alerts"][0]

        assert alert_data["raw"] == {}, f"raw must be {{}} when redaction active, got {alert_data['raw']!r}"

    def test_raw_preserved_when_no_redaction(self):
        """No-redact path: raw must be preserved verbatim (characterization)."""
        alert = _make_leaky_alert()
        enriched = enrich_alert_iocs(alert)
        report = _make_report(enriched)

        output = export_json(report)
        data = json.loads(output)
        alert_data = data["clusters"][0]["alerts"][0]

        # Without redaction, raw should still have the original message
        assert "message" in alert_data["raw"], "raw must be preserved when no redaction active"
        assert _SENSITIVE_IP in alert_data["raw"]["message"]

    def test_explicit_keep_raw_override_preserves_raw(self):
        """Forensic override: keep_raw=True preserves raw even when redaction active."""
        from sift.pipeline.redaction import redact_and_suppress_raw

        alert = _make_leaky_alert()
        result = redact_and_suppress_raw(alert, ["source_ip"], keep_raw=True)

        # keep_raw=True → raw must be preserved (forensic capture path)
        assert result.raw != {}, "keep_raw=True must preserve raw dict"
        assert result.source_ip == "[REDACTED]"


# ===========================================================================
# Section 2 — Channel 2: raw extraction must be gated when redaction active
# ===========================================================================


class TestChannel2RawExtractionGate:
    """_collect_text_fields must not mine raw when it is blanked."""

    def test_raw_blanked_means_no_raw_iocs_extracted(self):
        """After raw={}, enrich_alert_iocs must not extract _SENSITIVE_IP from raw."""
        alert = _make_leaky_alert()
        # Blank raw first (simulates Channel 1 suppression)
        blanked = alert.model_copy(update={"raw": {}, "source_ip": "[REDACTED]"})
        enriched = enrich_alert_iocs(blanked)

        assert _SENSITIVE_IP not in enriched.iocs, (
            f"Channel 2: {_SENSITIVE_IP!r} must not appear in iocs after raw blanked; got iocs={enriched.iocs!r}"
        )
        assert all(ioc.value != _SENSITIVE_IP for ioc in enriched.iocs_typed), (
            f"Channel 2: {_SENSITIVE_IP!r} must not appear in iocs_typed after raw blanked"
        )

    def test_raw_blanked_does_not_suppress_unrelated_iocs(self):
        """Channel 2 gate must only suppress raw extraction, not title/description IOCs."""
        alert = _make_leaky_alert(
            description="Scan activity — see also http://evil.example.com for context",
            raw={},
            source_ip="[REDACTED]",
        )
        enriched = enrich_alert_iocs(alert)
        # The URL from description must still be extracted
        assert any("evil.example.com" in ioc for ioc in enriched.iocs), (
            "IOCs from non-raw fields must still be extracted when raw is empty"
        )


# ===========================================================================
# Section 3 — Channel 3: drop IOCs matching redacted field values
# ===========================================================================


class TestChannel3IocDrop:
    def test_source_ip_value_not_in_iocs_after_drop(self):
        """Channel 3: after pipeline, _SENSITIVE_IP must not appear in iocs."""
        alert = _make_leaky_alert()
        enriched, redacted_values = _full_pipeline(alert, ["source_ip"])

        assert _SENSITIVE_IP not in enriched.iocs, (
            f"Channel 3: {_SENSITIVE_IP!r} must be dropped from iocs; got iocs={enriched.iocs!r}"
        )

    def test_source_ip_value_not_in_iocs_typed_after_drop(self):
        """Channel 3: after pipeline, _SENSITIVE_IP must not appear in iocs_typed."""
        alert = _make_leaky_alert()
        enriched, _ = _full_pipeline(alert, ["source_ip"])

        assert all(ioc.value != _SENSITIVE_IP for ioc in enriched.iocs_typed), (
            f"Channel 3: {_SENSITIVE_IP!r} must be dropped from iocs_typed"
        )

    def test_ioc_count_decreases_when_redaction_active(self):
        """IOC count must be <= count without redaction (known-expected behaviour)."""
        alert = _make_leaky_alert()
        enriched_no_redact = enrich_alert_iocs(alert)
        enriched_redacted, _ = _full_pipeline(alert, ["source_ip"])

        assert len(enriched_redacted.iocs) <= len(enriched_no_redact.iocs), "Redaction must not increase IOC count"
        # The no-redact version must have contained the sensitive value
        assert _SENSITIVE_IP in enriched_no_redact.iocs, "Baseline: no-redact pipeline must extract _SENSITIVE_IP"

    def test_channel3_known_residual_value_remains_in_description_text(self):
        """KNOWN RESIDUAL (documented): value in non-redacted description text is NOT removed.

        Phase 1 only drops the extracted IOC entry; the description text itself
        is not scrubbed (value-scrub was BLOCKED as unenumerable, deferred to Phase 2).
        Operators must also redact the field that carries the value
        (e.g. --redact-fields source_ip,description).

        This test records the residual as an explicit expectation so it is not
        a surprise — the description text DOES still contain the value.
        """
        alert = _make_leaky_alert(
            description=f"Scan from {_SENSITIVE_IP} detected on port 22",
        )
        enriched, redacted_values = _full_pipeline(alert, ["source_ip"])

        # The IOC entry is dropped (channel 3 works)
        assert _SENSITIVE_IP not in enriched.iocs, "Channel 3: extracted IOC must be dropped"

        # KNOWN RESIDUAL: description text still contains the value
        # This is deliberate — Phase 1 does not scrub text, only drops IOC entries.
        # Phase 2 (value-scrub) will address this.
        assert enriched.description is not None
        assert _SENSITIVE_IP in enriched.description, (
            "KNOWN RESIDUAL: description text is not scrubbed in Phase 1 "
            "(value-scrub deferred to Phase 2). "
            "Operator must also add 'description' to --redact-fields to remove it from text."
        )

    def test_channel3_known_residual_ip_inside_url_ioc_from_nonredacted_field(self):
        """KNOWN RESIDUAL (documented, pinned): redacted IP inside a URL IOC from a
        non-redacted field is NOT dropped by channel 3.

        Channel 3 uses exact-value matching: it drops IOCs whose .value EXACTLY
        equals a redacted value.  If the redacted value (e.g. "10.0.0.99") is a
        SUBSTRING of a larger extracted IOC (e.g. url "http://10.0.0.99/x"
        extracted from a non-redacted description field), the URL does not match
        and is therefore retained — the IP appears inside the URL IOC in all
        output formats.

        Root cause: substring matching was deliberately deferred to Phase 2
        (value-scrub) as it is unenumerable and risks over-dropping unrelated
        IOCs (MeetUp decision, 2026-06-12).

        Operator fix: also add the carrying field to --redact-fields
        (e.g. --redact-fields source_ip,description).  That blanks the field,
        preventing the larger IOC from being extracted at all.

        Phase 2 (value-scrub) is required to close this without manual field
        enumeration.
        """
        url_carrying_ip = f"http://{_SENSITIVE_IP}/malicious/path"
        alert = _make_leaky_alert(
            # description is NOT in the redact list — only source_ip is
            description=f"See {url_carrying_ip} for details",
        )
        enriched, redacted_values = _full_pipeline(alert, ["source_ip"])

        # The standalone IP IOC entry IS dropped (channel 3 still works for exact match)
        assert _SENSITIVE_IP not in enriched.iocs, (
            "Channel 3: standalone IP IOC must be dropped (exact-match drop works)"
        )

        # KNOWN RESIDUAL (IOC-substring form): the URL IOC containing the IP is NOT
        # dropped — it does not exactly equal the redacted value.
        # This is the pinned expectation: the URL still appears in iocs.
        # Phase 2 (value-scrub) deferred — do NOT switch channel 3 to substring drop.
        url_iocs_with_ip = [v for v in enriched.iocs if _SENSITIVE_IP in v and v != _SENSITIVE_IP]
        assert len(url_iocs_with_ip) > 0, (
            f"KNOWN RESIDUAL (IOC-substring): a URL/IOC containing {_SENSITIVE_IP!r} "
            "from a non-redacted field must still be present in iocs after Phase 1. "
            "This is deliberate — Phase 1 exact-match drop cannot close this without "
            "substring matching (deferred to Phase 2). "
            "Operator fix: add the carrying field ('description') to --redact-fields."
        )


# ===========================================================================
# Section 4 — All-formats absence scan (parametrized)
# ===========================================================================


def _render_console(report: TriageReport) -> str:
    """Render report to console format, capturing output."""
    from io import StringIO

    from rich.console import Console

    from sift.output.formatter import format_report_rich

    buf = StringIO()
    con = Console(file=buf, width=120, force_terminal=False, no_color=True)
    format_report_rich(report, console=con)
    return buf.getvalue()


@pytest.mark.parametrize(
    "fmt_name,render_fn",
    [
        ("json", lambda r: export_json(r)),
        ("html", lambda r: render_html_report(r)),
        ("md", lambda r: render_md_report(r)),
        ("stix", lambda r: STIXExporter(r).to_stix_bundle_string()),
        ("console", _render_console),
    ],
)
class TestAllFormatsAbsenceScan:
    """Sensitive value must not appear in ANY output format when redaction is active."""

    def test_sensitive_value_absent_from_all_formats_after_full_pipeline(self, fmt_name: str, render_fn):
        """All-formats absence scan: _SENSITIVE_IP must not appear in {fmt_name} output."""
        alert = _make_leaky_alert()

        # Run the full Phase 1 pipeline fix
        enriched, _ = _full_pipeline(alert, ["source_ip"])

        # Build cluster with enriched IOCs propagated
        cluster = Cluster(
            id=str(uuid.uuid4()),
            label="Port Scan Cluster",
            alerts=[enriched],
            priority=ClusterPriority.HIGH,
            score=10.0,
            iocs=enriched.iocs,
            iocs_typed=enriched.iocs_typed,
        )
        report = TriageReport(
            alerts_ingested=1,
            alerts_after_dedup=1,
            clusters=[cluster],
            analyzed_at=datetime.now(timezone.utc),
        )

        output_bytes = render_fn(report)
        if _SENSITIVE_IP in output_bytes:
            idx = output_bytes.find(_SENSITIVE_IP)
            context = output_bytes[max(0, idx - 40) : idx + 60]
            msg = (
                f"Format '{fmt_name}': {_SENSITIVE_IP!r} must not appear in output "
                f"after full pipeline. Found in: ...{context}..."
            )
            assert False, msg
        assert _SENSITIVE_IP not in output_bytes

    def test_no_redact_value_present_in_output(self, fmt_name: str, render_fn):
        """Characterization: without redaction, _SENSITIVE_IP IS present (baseline)."""
        alert = _make_leaky_alert()
        enriched = enrich_alert_iocs(alert)
        cluster = Cluster(
            id=str(uuid.uuid4()),
            label="Port Scan Cluster",
            alerts=[enriched],
            priority=ClusterPriority.HIGH,
            score=10.0,
            iocs=enriched.iocs,
            iocs_typed=enriched.iocs_typed,
        )
        report = TriageReport(
            alerts_ingested=1,
            alerts_after_dedup=1,
            clusters=[cluster],
            analyzed_at=datetime.now(timezone.utc),
        )
        output_bytes = render_fn(report)
        # Without redaction, the value MUST be present (confirms the test is real)
        assert _SENSITIVE_IP in output_bytes, (
            f"Format '{fmt_name}': baseline (no-redact) must have {_SENSITIVE_IP!r} present"
        )


# ===========================================================================
# Section 5 — Pipeline-level integration: redact_and_suppress_raw helper
# ===========================================================================


class TestRedactAndSuppressRaw:
    """redact_and_suppress_raw() — the Phase 1 pipeline boundary helper."""

    def test_blanks_raw_and_redacts_field(self):
        """Default (keep_raw=False): raw must be {} and field must be [REDACTED]."""
        from sift.pipeline.redaction import redact_and_suppress_raw

        alert = _make_leaky_alert()
        result = redact_and_suppress_raw(alert, ["source_ip"])

        assert result.source_ip == "[REDACTED]"
        assert result.raw == {}

    def test_keep_raw_true_preserves_raw(self):
        """keep_raw=True (forensic override): raw preserved, field still redacted."""
        from sift.pipeline.redaction import redact_and_suppress_raw

        alert = _make_leaky_alert()
        result = redact_and_suppress_raw(alert, ["source_ip"], keep_raw=True)

        assert result.source_ip == "[REDACTED]"
        assert result.raw != {}
        assert "message" in result.raw

    def test_get_redacted_values_captures_pre_redaction_values(self):
        """get_redacted_values() must return the actual string values before blanking."""
        from sift.pipeline.redaction import get_redacted_values

        alert = _make_leaky_alert(source_ip=_SENSITIVE_IP, user="jsmith")
        values = get_redacted_values(alert, ["source_ip", "user"])

        assert _SENSITIVE_IP in values
        assert "jsmith" in values

    def test_get_redacted_values_skips_iocs_and_raw(self):
        """get_redacted_values() must skip non-string fields (iocs/raw)."""
        from sift.pipeline.redaction import get_redacted_values

        alert = _make_leaky_alert()
        # These are non-string fields — should be skipped gracefully
        values = get_redacted_values(alert, ["source_ip", "iocs", "raw"])

        assert _SENSITIVE_IP in values
        # iocs and raw are not string fields — their lists/dicts are not added
        assert isinstance(values, set)

    def test_drop_redacted_iocs_removes_matching_values(self):
        """drop_redacted_iocs() must remove IOCs matching the redacted value set."""
        from sift.pipeline.redaction import drop_redacted_iocs

        iocs = ["10.0.0.99", "evil.com", "8.8.8.8"]
        typed = [
            IOC(value="10.0.0.99", type="ip"),
            IOC(value="evil.com", type="domain"),
            IOC(value="8.8.8.8", type="ip"),
        ]
        redacted_values = {"10.0.0.99"}

        clean_iocs, clean_typed = drop_redacted_iocs(iocs, typed, redacted_values)

        assert "10.0.0.99" not in clean_iocs
        assert all(ioc.value != "10.0.0.99" for ioc in clean_typed)
        assert "evil.com" in clean_iocs
        assert "8.8.8.8" in clean_iocs
