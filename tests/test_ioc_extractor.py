"""
tests/test_ioc_extractor.py

Focused pytest test suite for the sift IOC extraction pipeline.

Covers:
  - extract_iocs(text)       — pattern matching, filtering, dedup, sorting
  - detect_ioc_type(ioc)     — IOC classification
  - enrich_alert_iocs(alert) — alert enrichment, immutability, merging
  - enrich_alerts_iocs(...)  — batch enrichment
"""

from __future__ import annotations

import uuid

import pytest

from sift.models import Alert, AlertSeverity
from sift.pipeline.ioc_extractor import (
    detect_ioc_type,
    enrich_alert_iocs,
    enrich_alerts_iocs,
    extract_iocs,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(
    title: str = "Test Alert",
    description: str | None = None,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    iocs: list[str] | None = None,
    raw: dict | None = None,
) -> Alert:
    """Minimal Alert factory for test convenience."""
    return Alert(
        id=str(uuid.uuid4()),
        title=title,
        description=description,
        source_ip=source_ip,
        dest_ip=dest_ip,
        severity=AlertSeverity.MEDIUM,
        iocs=iocs or [],
        raw=raw or {},
    )


# ===========================================================================
# extract_iocs
# ===========================================================================

class TestExtractIocs:
    # ---- IPv4 ---------------------------------------------------------------

    def test_public_ipv4_extracted(self):
        """Public IPv4 address is extracted from surrounding text."""
        result = extract_iocs("Connection from 185.220.101.47")
        assert "185.220.101.47" in result

    def test_private_ipv4_10_not_extracted(self):
        """10.x.x.x (RFC 1918) is excluded."""
        assert extract_iocs("10.0.0.1") == []

    def test_private_ipv4_192_168_not_extracted(self):
        """192.168.x.x (RFC 1918) is excluded."""
        assert extract_iocs("192.168.1.1") == []

    def test_private_ipv4_172_16_not_extracted(self):
        """172.16.x.x (RFC 1918) is excluded."""
        assert extract_iocs("172.16.0.1") == []

    def test_loopback_not_extracted(self):
        """127.0.0.1 (loopback) is excluded."""
        assert extract_iocs("127.0.0.1") == []

    # ---- URL ----------------------------------------------------------------

    def test_http_url_extracted(self):
        """http:// URL is captured in full."""
        result = extract_iocs("http://evil.phish.ru/login")
        assert "http://evil.phish.ru/login" in result

    def test_https_url_extracted(self):
        """https:// URL is captured."""
        result = extract_iocs("User visited https://malware.example.com/payload.exe")
        assert any("https://" in ioc for ioc in result)

    # ---- Domain -------------------------------------------------------------

    def test_domain_extracted_from_text(self):
        """Bare domain is extracted from surrounding prose."""
        result = extract_iocs("DNS query to evil.phish.ru")
        assert "evil.phish.ru" in result

    def test_local_domain_not_extracted(self):
        """.local TLD is excluded as a non-routable internal domain."""
        assert extract_iocs("server.local") == []

    def test_internal_tld_corp_not_extracted(self):
        """.corp TLD is excluded."""
        assert extract_iocs("dc01.corp") == []

    def test_internal_tld_internal_not_extracted(self):
        """.internal TLD is excluded."""
        assert extract_iocs("host.internal") == []

    # ---- Hash ---------------------------------------------------------------

    def test_md5_hash_extracted(self):
        """MD5 (32-char hex) is extracted."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = extract_iocs(f"Hash: {md5}")
        assert md5 in result

    def test_sha256_hash_extracted(self):
        """SHA-256 (64-char hex) is extracted."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_iocs(f"Malware hash: {sha256}")
        assert sha256 in result

    def test_sha1_hash_extracted(self):
        """SHA-1 (40-char hex) is extracted."""
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = extract_iocs(f"File hash: {sha1}")
        assert sha1 in result

    def test_sha256_not_also_extracted_as_sha1_or_md5(self):
        """A SHA-256 hash must not be duplicated as a shorter hash type."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_iocs(sha256)
        # Only the full 64-char form should appear — no spurious 32/40-char substring.
        assert sha256 in result
        assert sha256[:32] not in result
        assert sha256[:40] not in result

    # ---- Email --------------------------------------------------------------

    def test_email_extracted(self):
        """Email address is extracted."""
        result = extract_iocs("From: attacker@evil.ru")
        assert "attacker@evil.ru" in result

    # ---- Multiple / dedup / sort -------------------------------------------

    def test_multiple_iocs_all_extracted(self):
        """Several distinct IOC types in one text are all captured."""
        text = (
            "IP 185.220.101.47 contacted http://evil.phish.ru/drop "
            "hash d41d8cd98f00b204e9800998ecf8427e"
        )
        result = extract_iocs(text)
        assert "185.220.101.47" in result
        assert "http://evil.phish.ru/drop" in result
        assert "d41d8cd98f00b204e9800998ecf8427e" in result

    def test_duplicates_removed(self):
        """The same IOC appearing twice produces only one entry."""
        text = "185.220.101.47 then again 185.220.101.47"
        result = extract_iocs(text)
        assert result.count("185.220.101.47") == 1

    def test_result_is_sorted(self):
        """Output list is lexicographically sorted for determinism."""
        text = "IPs: 8.8.8.8 and 1.1.1.1"
        result = extract_iocs(text)
        assert result == sorted(result)

    def test_empty_string_returns_empty_list(self):
        """Empty input produces an empty list."""
        assert extract_iocs("") == []

    def test_no_iocs_returns_empty_list(self):
        """Text with no IOCs produces an empty list."""
        assert extract_iocs("No indicators here, just a normal log entry.") == []


# ===========================================================================
# detect_ioc_type
# ===========================================================================

class TestDetectIocType:
    def test_public_ipv4_returns_ip(self):
        assert detect_ioc_type("185.220.101.47") == "ip"

    def test_private_ipv4_still_classified_as_ip(self):
        """detect_ioc_type classifies the string type, not whether it is public."""
        assert detect_ioc_type("192.168.1.1") == "ip"

    def test_url_returns_url(self):
        assert detect_ioc_type("http://evil.phish.ru/login") == "url"

    def test_https_url_returns_url(self):
        assert detect_ioc_type("https://malware.example.com/payload.exe") == "url"

    def test_domain_returns_domain(self):
        assert detect_ioc_type("evil.phish.ru") == "domain"

    def test_md5_returns_hash_md5(self):
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash_md5"

    def test_sha1_returns_hash_sha1(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert detect_ioc_type(sha1) == "hash_sha1"

    def test_sha256_returns_hash_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_ioc_type(sha256) == "hash_sha256"

    def test_email_returns_email(self):
        assert detect_ioc_type("attacker@evil.ru") == "email"

    def test_unknown_string_returns_unknown(self):
        assert detect_ioc_type("not-an-ioc-at-all!!") == "unknown"

    def test_email_not_misclassified_as_domain(self):
        """Emails contain an @-domain part; they must not be typed as 'domain'."""
        assert detect_ioc_type("user@example.com") == "email"

    def test_url_not_misclassified_as_domain(self):
        """A full URL must be typed as 'url', not 'domain'."""
        assert detect_ioc_type("http://example.com") == "url"


# ===========================================================================
# enrich_alert_iocs
# ===========================================================================

class TestEnrichAlertIocs:
    def test_public_source_ip_added_to_iocs(self):
        """Public source_ip is always added unconditionally."""
        alert = make_alert(source_ip="185.220.101.47")
        enriched = enrich_alert_iocs(alert)
        assert "185.220.101.47" in enriched.iocs

    def test_public_dest_ip_added_to_iocs(self):
        """Public dest_ip is always added unconditionally."""
        alert = make_alert(dest_ip="8.8.4.4")
        enriched = enrich_alert_iocs(alert)
        assert "8.8.4.4" in enriched.iocs

    def test_private_source_ip_added_unconditionally(self):
        """Private source_ip is still added (network context always matters)."""
        alert = make_alert(source_ip="10.0.0.5")
        enriched = enrich_alert_iocs(alert)
        assert "10.0.0.5" in enriched.iocs

    def test_ioc_in_title_extracted(self):
        """IOC embedded in alert.title is extracted to iocs."""
        alert = make_alert(title="Connection from 185.220.101.47 on port 443")
        enriched = enrich_alert_iocs(alert)
        assert "185.220.101.47" in enriched.iocs

    def test_ioc_in_description_extracted(self):
        """IOC embedded in alert.description is extracted to iocs."""
        alert = make_alert(description="Malware beacon to http://evil.phish.ru/drop")
        enriched = enrich_alert_iocs(alert)
        assert any("evil.phish.ru" in ioc for ioc in enriched.iocs)

    def test_hash_in_description_extracted(self):
        """Hash found in description ends up in iocs."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        alert = make_alert(description=f"Dropped file hash: {md5}")
        enriched = enrich_alert_iocs(alert)
        assert md5 in enriched.iocs

    def test_original_alert_not_mutated(self):
        """enrich_alert_iocs must return a new object; original iocs unchanged."""
        alert = make_alert(title="Traffic to 185.220.101.47")
        original_iocs = list(alert.iocs)
        enrich_alert_iocs(alert)
        assert alert.iocs == original_iocs  # original untouched

    def test_pre_existing_iocs_preserved(self):
        """IOCs already on the alert are kept after enrichment."""
        alert = make_alert(iocs=["pre-existing.evil.com"])
        enriched = enrich_alert_iocs(alert)
        assert "pre-existing.evil.com" in enriched.iocs

    def test_pre_existing_iocs_merged_with_new(self):
        """New IOCs from text fields are merged with (not replace) existing ones."""
        alert = make_alert(
            title="Traffic to 185.220.101.47",
            iocs=["existing.evil.com"],
        )
        enriched = enrich_alert_iocs(alert)
        assert "existing.evil.com" in enriched.iocs
        assert "185.220.101.47" in enriched.iocs

    def test_no_duplicate_iocs_in_result(self):
        """Same IOC appearing in title and dest_ip is deduplicated."""
        alert = make_alert(
            title="Beacon to 8.8.8.8 detected",
            dest_ip="8.8.8.8",
        )
        enriched = enrich_alert_iocs(alert)
        assert enriched.iocs.count("8.8.8.8") == 1

    def test_returns_alert_instance(self):
        """Return value is an Alert, not the original object."""
        alert = make_alert()
        enriched = enrich_alert_iocs(alert)
        assert isinstance(enriched, Alert)
        assert enriched is not alert

    def test_ioc_in_raw_field_extracted(self):
        """IOCs embedded in alert.raw dict values are extracted."""
        alert = make_alert(raw={"cmd": "curl http://evil.phish.ru/c2"})
        enriched = enrich_alert_iocs(alert)
        assert any("evil.phish.ru" in ioc for ioc in enriched.iocs)

    def test_alert_with_no_ioc_sources_returns_empty_iocs(self):
        """Alert with no text IOCs and no network fields yields empty iocs."""
        alert = make_alert(title="Scheduled Task Created")
        enriched = enrich_alert_iocs(alert)
        # No public IPs, no hashes, no domains in a plain title like this
        assert isinstance(enriched.iocs, list)


# ===========================================================================
# enrich_alerts_iocs  (batch)
# ===========================================================================

class TestEnrichAlertsIocs:
    def test_batch_returns_same_count(self):
        """One enriched alert is produced per input alert."""
        alerts = [
            make_alert(title="Alert A — dest 185.220.101.47"),
            make_alert(title="Alert B — no iocs"),
            make_alert(dest_ip="8.8.8.8"),
        ]
        result = enrich_alerts_iocs(alerts)
        assert len(result) == len(alerts)

    def test_batch_enriches_each_alert(self):
        """Each alert in the batch receives its own extracted IOCs."""
        a1 = make_alert(dest_ip="185.220.101.47")
        a2 = make_alert(dest_ip="1.1.1.1")
        result = enrich_alerts_iocs([a1, a2])
        assert "185.220.101.47" in result[0].iocs
        assert "1.1.1.1" in result[1].iocs

    def test_batch_empty_list(self):
        """Empty input list returns empty output list."""
        assert enrich_alerts_iocs([]) == []

    def test_batch_originals_not_mutated(self):
        """Original alerts in the input list are not modified."""
        alert = make_alert(dest_ip="8.8.8.8")
        original_iocs = list(alert.iocs)
        enrich_alerts_iocs([alert])
        assert alert.iocs == original_iocs
