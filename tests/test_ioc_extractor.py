"""
tests/test_ioc_extractor.py

Focused pytest test suite for the sift IOC extraction pipeline.

Covers:
  - extract_iocs(text)       — pattern matching, filtering, dedup, sorting
  - detect_ioc_type(ioc)     — IOC classification
  - enrich_alert_iocs(alert) — alert enrichment, immutability, merging
  - enrich_alerts_iocs(...)  — batch enrichment
  - _refang(text)            — defang preprocessor (bracketed scheme, word-form dots)
"""

from __future__ import annotations

import time
import uuid

import pytest

from sift.models import IOC, Alert, AlertSeverity
from sift.pipeline.ioc_extractor import (
    _refang,
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
        md5 = "5d41402abc4b2a76b9719d911017c592"
        result = extract_iocs(f"Hash: {md5}")
        assert md5 in result

    def test_sha256_hash_extracted(self):
        """SHA-256 (64-char hex) is extracted."""
        sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        result = extract_iocs(f"Malware hash: {sha256}")
        assert sha256 in result

    def test_sha1_hash_extracted(self):
        """SHA-1 (40-char hex) is extracted."""
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        result = extract_iocs(f"File hash: {sha1}")
        assert sha1 in result

    def test_sha256_not_also_extracted_as_sha1_or_md5(self):
        """A SHA-256 hash must not be duplicated as a shorter hash type."""
        sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
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
        text = "IP 185.220.101.47 contacted http://evil.phish.ru/drop hash 5d41402abc4b2a76b9719d911017c592"
        result = extract_iocs(text)
        assert "185.220.101.47" in result
        assert "http://evil.phish.ru/drop" in result
        assert "5d41402abc4b2a76b9719d911017c592" in result

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
        assert detect_ioc_type("5d41402abc4b2a76b9719d911017c592") == "hash_md5"

    def test_sha1_returns_hash_sha1(self):
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        assert detect_ioc_type(sha1) == "hash_sha1"

    def test_sha256_returns_hash_sha256(self):
        sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
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
        md5 = "5d41402abc4b2a76b9719d911017c592"
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


# ===========================================================================
# _refang — defang preprocessor gaps (bracketed scheme separator + (dot))
# ===========================================================================


class TestRefang:
    # ---- Bracketed scheme separator [://] -----------------------------------

    def test_bracketed_scheme_https_refanged(self):
        """hxxps[://] is refanged to https:// (full round-trip)."""
        assert _refang("hxxps[://]evil[.]com/login") == "https://evil.com/login"

    def test_bracketed_scheme_http_refanged(self):
        """hxxp[://] is refanged to http:// (full round-trip)."""
        assert _refang("hxxp[://]1[.]2[.]3[.]4") == "http://1.2.3.4"

    def test_bracketed_scheme_extracted_as_url(self):
        """IOC extraction recognises a hxxps[://] URL and restores it."""
        result = extract_iocs("beacon to hxxps[://]evil[.]com/drop")
        assert "https://evil.com/drop" in result

    def test_bracketed_scheme_ip_extracted_as_url(self):
        """hxxp[://] with a dotted-quad IP round-trips through extract_iocs."""
        result = extract_iocs("hxxp[://]198.51.100.1/payload")
        assert "http://198.51.100.1/payload" in result

    # ---- (dot) word-form separator ------------------------------------------

    def test_dot_paren_refanged(self):
        """(dot) word form is converted to a literal dot."""
        assert _refang("evil(dot)com") == "evil.com"

    def test_dot_paren_case_insensitive(self):
        """(DOT) and (Dot) are treated the same as (dot)."""
        assert _refang("evil(DOT)com") == "evil.com"
        assert _refang("evil(Dot)com") == "evil.com"

    def test_dot_paren_extracted_as_domain(self):
        """IOC extraction recognises a (dot)-defanged domain."""
        result = extract_iocs("DNS query to evil(dot)phish(dot)ru")
        assert "evil.phish.ru" in result

    # ---- Existing forms still work (non-regression) -------------------------

    def test_bracket_dot_still_refanged(self):
        """[.] (original pattern) is still handled after adding (dot)."""
        assert _refang("evil[.]com") == "evil.com"

    def test_brace_dot_still_refanged(self):
        """{.} is still handled."""
        assert _refang("evil{.}com") == "evil.com"

    def test_bracket_dot_word_still_refanged(self):
        """[dot] word-form is still handled."""
        assert _refang("evil[dot]com") == "evil.com"

    # ---- IPv6 preserved (must not be corrupted by refang) -------------------

    def test_ipv6_loopback_preserved(self):
        """IPv6 literal ``http://[::1]/x`` passes through _refang unchanged."""
        assert _refang("http://[::1]/x") == "http://[::1]/x"

    def test_ipv6_full_address_preserved(self):
        """A routable IPv6 address in a URL is not corrupted."""
        url = "http://[2001:db8::1]/path"
        assert _refang(url) == url

    # ---- Idempotency --------------------------------------------------------

    def test_idempotent_bracketed_scheme(self):
        """Running _refang twice on hxxps[://] input equals running it once."""
        inp = "hxxps[://]evil[.]com/login"
        assert _refang(_refang(inp)) == _refang(inp)

    def test_idempotent_dot_paren(self):
        """Running _refang twice on (dot) input equals running it once."""
        inp = "evil(dot)com"
        assert _refang(_refang(inp)) == _refang(inp)

    def test_idempotent_plain_url(self):
        """Running _refang twice on an already-clean URL is a no-op."""
        url = "https://google.com"
        assert _refang(_refang(url)) == _refang(url) == url


# ---------------------------------------------------------------------------
# Task 3 — enrich_alert_iocs populates iocs_typed
# ---------------------------------------------------------------------------


class TestEnrichAlertIocsTyped:
    def test_enrich_populates_iocs_typed(self):
        """After enrich_alert_iocs, iocs_typed has entries with correct types."""
        sha256 = "a" * 64
        alert = make_alert(
            title="Connection from 1.2.3.4",
            description=f"Dropped file hash: {sha256}",
        )
        enriched = enrich_alert_iocs(alert)

        # iocs_typed must be populated
        assert enriched.iocs_typed, "iocs_typed must not be empty after enrichment"

        # The set of typed values must equal the set of iocs strings
        typed_values = {ioc.value for ioc in enriched.iocs_typed}
        assert typed_values == set(enriched.iocs), "iocs_typed values must match iocs strings"

        # Every entry must have type == detect_ioc_type(value)
        for ioc in enriched.iocs_typed:
            expected_type = detect_ioc_type(ioc.value)
            assert ioc.type == expected_type, (
                f"Type mismatch for {ioc.value!r}: got {ioc.type!r}, expected {expected_type!r}"
            )

    def test_enrich_typed_values_are_ioc_instances(self):
        """iocs_typed entries must be IOC model instances."""
        alert = make_alert(title="Test 185.220.101.47")
        enriched = enrich_alert_iocs(alert)
        for entry in enriched.iocs_typed:
            assert isinstance(entry, IOC)

    def test_enrich_iocs_unchanged(self):
        """enrich_alert_iocs must NOT change the type/shape of iocs (still list[str])."""
        alert = make_alert(title="Test 185.220.101.47")
        enriched = enrich_alert_iocs(alert)
        assert isinstance(enriched.iocs, list)
        assert all(isinstance(v, str) for v in enriched.iocs)


# ---------------------------------------------------------------------------
# Domain regex: linear time on dotted/hyphenated runs
# ---------------------------------------------------------------------------

_REDOS_SHAPES = {
    "unicode_dotted": "é.",
    "unicode_label": "éa",
    "unicode_hyphen": "é-",
    "a.": "a.",
    "a.b-": "a.b-",
    "a-b.": "a-b.",
    "a.b.c-": "a.b.c-",
    "a.b-c": "a.b-c",
}


def _timed_extract(text: str) -> float:
    start = time.perf_counter()
    extract_iocs(text)
    return time.perf_counter() - start


@pytest.mark.parametrize("unit", list(_REDOS_SHAPES.values()), ids=list(_REDOS_SHAPES))
def test_domain_regex_linear_time(unit: str) -> None:
    small = unit * (80_000 // len(unit)) + "1"
    big = unit * (400_000 // len(unit)) + "1"
    t_small = _timed_extract(small)
    assert t_small < 1.0  # checked before the big case so a regression fails fast instead of hanging
    t_big = _timed_extract(big)
    assert t_big < 1.0
    # Five times the input must cost about five times the time, not twenty-five.
    assert t_big / max(t_small, 0.01) < 10


@pytest.mark.parametrize("text", ["*.evil.com", ".evil.com", "x..evil.com", "see http://x.evil.com/p", "a.b.evil.com"])
def test_domain_regex_still_extracts_suffix_domains(text: str) -> None:
    values = set(extract_iocs(text))
    assert values & {"evil.com", "x.evil.com", "a.b.evil.com"}, values


_UNDERSCORE_SHAPES = {
    "dmarc": ("query _dmarc.evil.com TXT", "evil.com"),
    "srv": ("srv _ldap._tcp.evil.com", "evil.com"),
    "assign": ("host=_x.evil.com", "evil.com"),
    "path": ("path/_x.evil.com", "evil.com"),
    "double": ("q__x.evil.com", "evil.com"),
    "glued": ("ping foo_bar.evil.com", "evil.com"),
    "glued_sub": ("beacon to web_01.c2.evil.com", "c2.evil.com"),
    "x_y": ("x_y.evil.com", "evil.com"),
    "leading": ("_x.evil.com", "evil.com"),
    "label_64": ("q " + "a" * 64 + ".evil.com", "evil.com"),
    "label_70_sub": ("q " + "a" * 70 + ".c2.evil.com", "c2.evil.com"),
    "hyphen_end": ("see x-.evil.com now", "evil.com"),
    "hyphen_lead": ("see -abc.evil.com now", "abc.evil.com"),
    "suffix_before_bad_label": ("evil.com._x.foo.bar", "evil.com"),
}


@pytest.mark.parametrize(("text", "expected"), list(_UNDERSCORE_SHAPES.values()), ids=list(_UNDERSCORE_SHAPES))
def test_domain_extracted_despite_underscore_or_invalid_label(text: str, expected: str) -> None:
    # An attacker must not hide a domain by gluing "_x." or an over-long label in front of it.
    assert expected in extract_iocs(text)


def test_domain_scan_matches_strict_pattern_on_label_edge_cases() -> None:
    # The linear scanner must give what the strict per-label pattern gives, text by text.
    from sift.pipeline.ioc_extractor import _RE_DOMAIN, _scan_domains

    texts = [
        "c.bb-.cb",
        "evil.com._x.foo",
        "a.b.c.com_x.org",
        "x1." + "a" * 64 + ".b-",
        "ab-c.de-fg.hi",
        "a..b.com",
        ".-evil.com",
    ]
    for text in texts:
        assert _scan_domains(text) == [m.group() for m in _RE_DOMAIN.finditer(text)], text


def test_domain_scan_long_underscore_runs_are_linear() -> None:
    for unit in ("_a.", "a_.", "a-_.", "a." * 3 + "_"):
        text = unit * (400_000 // len(unit)) + "_x.evil.com"
        assert _timed_extract(text) < 2.0, unit


def test_hash_dedupe_scales_linearly() -> None:
    # 20,000 distinct MD5s: the pairwise prefix scan took ~13 s; the prefix index takes well under 1 s.
    text = " ".join(f"{i:032x}" for i in range(1, 20_001))
    start = time.perf_counter()
    found = extract_iocs(text)
    elapsed = time.perf_counter() - start
    assert len(found) == 20_000
    assert elapsed < 3.0


def test_hash_that_prefixes_a_longer_candidate_is_still_suppressed() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    other = "d41d8cd98f00b204e9800998ecf8427f"
    found = extract_iocs(f"{md5}.evil.com and {other}")
    assert f"{md5}.evil.com" in found
    assert md5 not in found
    assert other in found


@pytest.mark.parametrize(
    ("length", "tail"),
    [(64, "c3" * 32), (62, "c3"), (40, ".evil.com"), (32, ".evil.com")],
    ids=["sha256", "jarm", "sha1", "md5"],
)
def test_each_hash_kind_is_prefix_suppressed_by_a_longer_candidate(length: int, tail: str) -> None:
    h = "a1" * (length // 2)
    found = extract_iocs(f"{h}{tail} and {h}")
    assert f"{h}{tail}" in found
    assert h not in found


def test_email_still_extracted_and_local_part_capped() -> None:
    assert "bob.harris+tag@evil.com" in extract_iocs("mail bob.harris+tag@evil.com now")
    # A local part over the RFC 5321 limit of 64 is not an address: no email IOC, the domain still counts.
    found = extract_iocs("x" * 70 + "@evil.com")
    assert not [v for v in found if "@" in v]
    assert found.count("evil.com") == 1


def test_email_local_part_boundary_is_exactly_64() -> None:
    ok = "x" * 64 + "@evil.com"
    assert ok in extract_iocs(f"mail {ok} now")
    assert not [v for v in extract_iocs("mail " + "x" * 65 + "@evil.com now") if "@" in v]


_UNICODE_DOMAIN_CASES = {
    "bucher_prose": ("visit bücher.example.com now", ["example.com"]),
    "bucher_url": ("http://bücher.example.com/x", ["example.com"]),
    "arzte": ("Ärzte.example.org", ["example.org"]),
    "munchen_koln": ("münchen.de und köln.de", []),
    "grosse": ("Größe.Info", []),
    "e_acute_label": ("é.evil.com", ["evil.com"]),
    "cyrillic_a_glued": ("\u0430evil.com", []),
    "kelvin_glued": ("\u212aevil.com", []),
    "dotless_i_glued": ("\u0131evil.com", []),
}


@pytest.mark.parametrize(("text", "expected"), list(_UNICODE_DOMAIN_CASES.values()), ids=list(_UNICODE_DOMAIN_CASES))
def test_domain_scan_is_unicode_word_aware(text: str, expected: list[str]) -> None:
    # A non-ASCII letter glued to a label is part of that label: no fabricated sub-label domain.
    from sift.pipeline.ioc_extractor import _scan_domains

    assert _scan_domains(text) == expected


def test_domain_scan_matches_frozen_main_pattern_on_unicode_alphabet() -> None:
    import random
    import re

    from sift.pipeline.ioc_extractor import _scan_domains

    # Frozen copy of origin/main's domain pattern (it used \b, which is Unicode-aware).
    main = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
    alphabet = ["a", "b", "1", "-", ".", ".", "é", "ß", "٣", "ａ", "İ", "а", "K", "ı", " "]
    rng = random.Random(4571)
    for _ in range(4000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 16)))
        assert _scan_domains(text) == [m.group() for m in main.finditer(text)], repr(text)


@pytest.mark.parametrize(
    "text",
    [
        "9" + "a" * 65 + "%@a.uk",
        "a" * 64 + "(dot).com.orgb@123-.COM",
        "q " + "a." * 40 + "b@evil.com",
        "x-" * 40 + "y@evil.com",
    ],
    ids=["percent_tail", "dot_tail", "dotted_run", "hyphen_run"],
)
def test_over_long_email_local_part_yields_no_fragment(text: str) -> None:
    assert not [v for v in extract_iocs(text) if "@" in v]


def test_email_with_local_part_after_other_text_still_extracted() -> None:
    assert "a.b@evil.com" in extract_iocs("(a.b@evil.com)")
    assert "ab@evil.com" in extract_iocs("--ab@evil.com")
    assert "a" * 64 + "@evil.com" in extract_iocs(" " + "a" * 64 + "@evil.com")
    assert "ab@evil.com" in extract_iocs("-" * 70 + " ab@evil.com")


@pytest.mark.parametrize(
    ("lead", "sep"),
    [("x", "."), ("x", "%"), ("x", "+"), ("x", "-"), ("a", "%"), ("Z", "%"), ("9", "%"), ("_", ".")],
)
def test_over_long_email_run_is_dropped_whatever_its_characters(lead: str, sep: str) -> None:
    # 65 local-part characters, with a word boundary inside: the last 63/64 must not surface as an address.
    text = f"{lead}{sep}" + "a" * 63 + "@evil.com"
    assert not [v for v in extract_iocs(text) if "@" in v], text


def test_email_local_part_of_exactly_64_after_a_boundary_character_is_kept() -> None:
    # The run is "." + 63 letters = 64 characters; the match starts after the "." (no boundary before it).
    assert "a" * 63 + "@evil.com" in extract_iocs(" ." + "a" * 63 + "@evil.com")


def _emails(text: str) -> list[str]:
    return [v for v in extract_iocs(text) if "@" in v]


_A64 = "a" * 64

# (text, emails origin/main extracted). Main starts an address at the leftmost word boundary of the
# run of local-part characters, so a leading ". % + -" is never part of its local part.
_EMAIL_KEPT_CASES = {
    "dash_70": ("-" * 70 + "john@example.com", ["john@example.com"]),
    "dot_70": ("." * 70 + "john@example.com", ["john@example.com"]),
    "plus_66": ("+" * 66 + "john@example.com", ["john@example.com"]),
    "percent_70": ("%" * 70 + "john@example.com", ["john@example.com"]),
    "dash_63_c2": ("-" * 63 + "c2@evil.com", ["c2@evil.com"]),
    "dot_then_64a": ("." + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "percent_then_64a": ("%" + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "dash_70_then_64a": ("-" * 70 + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "dot_70_then_64a": ("." * 70 + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "plus_66_then_64a": ("+" * 66 + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "slash_then_64a": ("/" + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "paren_then_64a": ("(" + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "word_slash_then_64a": ("z/" + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "word_paren_then_64a": ("z(" + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "word_colon_then_64a": ("z:" + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "word_space_then_64a": ("z " + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "earlier_at_then_64a": ("z@" + _A64 + "@evil.com", [_A64 + "@evil.com"]),
    "underscore_dot_then_62a": ("_." + "a" * 62 + "@evil.com", ["_." + "a" * 62 + "@evil.com"]),
    "dot_then_63a": (" ." + "a" * 63 + "@evil.com", ["a" * 63 + "@evil.com"]),
}


@pytest.mark.parametrize(("text", "expected"), list(_EMAIL_KEPT_CASES.values()), ids=list(_EMAIL_KEPT_CASES))
def test_email_whose_local_part_is_at_most_64_from_where_the_old_pattern_started_is_kept(
    text: str, expected: list[str]
) -> None:
    assert _emails(text) == expected


_EMAIL_DROPPED_CASES = {
    "dot_then_63a_after_letter": "x." + "a" * 63 + "@evil.com",
    "65a": "a" * 65 + "@evil.com",
    "65a_after_space": " " + "a" * 65 + "@evil.com",
    "underscore_dot_63a": "_." + "a" * 63 + "@evil.com",
    "underscore_dot_64a": "_." + _A64 + "@evil.com",
    "letter_dash_70_then_64a": "x" + "-" * 70 + _A64 + "@evil.com",
    "dash_run_after_letter": "x" + "-" * 70 + "c2@evil.com",
    "acute_then_dash_64a": "\u00e9-" + _A64 + "@evil.com",
}


@pytest.mark.parametrize("text", list(_EMAIL_DROPPED_CASES.values()), ids=list(_EMAIL_DROPPED_CASES))
def test_email_whose_local_part_is_over_64_from_where_the_old_pattern_started_is_dropped(text: str) -> None:
    assert _emails(text) == []


def test_glued_unicode_word_character_hides_the_email_exactly_as_main_did() -> None:
    # No word boundary between an accented letter and the local part: main (and now) find no address.
    assert _emails("\u00e9" + _A64 + "@evil.com") == []
    assert _emails("\u00e9" + "a" * 10 + "@evil.com") == []
    assert _emails("\u0663" + "a" * 10 + "@evil.com") == []


def test_second_email_after_an_earlier_at_is_found_from_its_own_position() -> None:
    text = "x@y.zz " + "a" * 65 + "%@a.uk ok@fine.org"
    assert sorted(_emails(text)) == ["ok@fine.org", "x@y.zz"]


def test_email_directly_after_a_dropped_address_domain_is_not_resurrected() -> None:
    # Main's long match consumed "x.com"; the glued "@y.org" never had a local part of its own.
    assert _emails("a" + "." * 100 + "@x.com@y.org") == []


def test_scan_emails_returns_exactly_the_old_match_for_kept_and_dropped() -> None:
    import re

    from sift.pipeline.ioc_extractor import _scan_emails

    main = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
    text = "-" * 70 + "john@example.com x." + "a" * 63 + "@evil.com _." + "a" * 62 + "@evil.com"
    kept, dropped = _scan_emails(text)
    assert kept == ["john@example.com", "_." + "a" * 62 + "@evil.com"]
    assert dropped == ["x." + "a" * 63 + "@evil.com"]
    assert sorted(kept + dropped) == sorted(m.group() for m in main.finditer(text))


def test_email_scan_matches_frozen_main_pattern_minus_over_long_local_parts() -> None:
    import random
    import re

    from sift.pipeline.ioc_extractor import _scan_emails

    # Frozen copy of origin/main's email pattern. Invariant: kept == main's addresses with a local
    # part of at most 64, dropped == the rest; nothing else, nothing different.
    main = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
    seps = [".", "-", "%", "+", "_", ".-"]
    alphabet = ["a", "b", "1", "\u00e9", "\u0663", "@", "/", ":", " ", "\u00df", "\u0301", "\u200d"]
    ends = ["@evil.com", "@a.b.org", "@x.com@y.org", "%@a.uk", " x@evil.com", "@a.b"]
    lens = [1, 2, 3, 30, 62, 63, 64, 65, 66, 70]
    rng = random.Random(4572)
    for _ in range(3000):
        parts = []
        for _ in range(rng.randint(1, 4)):
            r = rng.random()
            if r < 0.4:
                parts.append(rng.choice(seps) * rng.choice(lens))
            elif r < 0.6:
                parts.append(rng.choice("abc9") * rng.choice(lens))
            elif r < 0.8:
                parts.append("".join(rng.choice(alphabet) for _ in range(rng.randint(1, 6))))
            else:
                parts.append(rng.choice(ends))
        text = "".join(parts) + rng.choice(ends)
        expected = [m.group() for m in main.finditer(text)]
        kept, dropped = _scan_emails(text)
        assert kept == [e for e in expected if len(e.split("@")[0]) <= 64], repr(text)
        assert dropped == [e for e in expected if len(e.split("@")[0]) > 64], repr(text)


@pytest.mark.parametrize(
    ("text", "hash_len"),
    [
        ("a" * 64 + "+bAc@9.c.com", 64),
        ("a" * 62 + "+bAc@9.c.com", 62),
        ("a" * 40 + ".." + "b" * 30 + "@evil.com", 40),
        ("a" * 32 + "-" + "b" * 40 + "@evil.com", 32),
    ],
    ids=["sha256", "jarm", "sha1", "md5"],
)
def test_hash_shaped_prefix_of_a_dropped_email_stays_hidden_as_on_main(text: str, hash_len: int) -> None:
    # The over-long address is not an IOC, but main hid its hash-shaped prefix behind it; so do we.
    found = extract_iocs(text)
    assert not [v for v in found if "@" in v]
    assert text[:hash_len] not in found


@pytest.mark.parametrize("sep", [".", "%", "+", "-"])
def test_over_long_email_run_is_dropped_when_the_separator_is_left_of_the_match(sep: str) -> None:
    # The match starts after the separator (64 letters), so the check has to walk back across it.
    text = f"x{sep}" + "a" * 64 + "@evil.com"
    assert not [v for v in extract_iocs(text) if "@" in v], text


# --- detect_ioc_type must classify emails exactly as origin/main did (no local-part cap) ---

# Frozen copy of origin/main's classification pattern (unbounded local part, Unicode-aware \b).
_MAIN_EMAIL_FULL = __import__("re").compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")


@pytest.mark.parametrize("n", [1, 63, 64, 65, 100, 1000])
def test_detect_ioc_type_email_has_no_local_part_cap(n: int) -> None:
    assert detect_ioc_type("a" * n + "@x.com") == "email"


@pytest.mark.parametrize("n", [63, 64, 65, 100])
def test_detect_ioc_type_still_rejects_malformed_emails_at_any_length(n: int) -> None:
    assert detect_ioc_type("a" * n + "@x") != "email"
    assert detect_ioc_type("a" * n + "@@x.com") != "email"
    assert detect_ioc_type("@x.com") != "email"
    assert detect_ioc_type("." * n + "@x.co") != "email"  # main: \b fails at a leading "."


def test_detect_ioc_type_matches_frozen_main_pattern_on_unicode_alphabet() -> None:
    import random

    alphabet = ["a", "Z", "1", "-", ".", "_", "%", "+", "@", "@", "é", "ß", "٣", "ａ", "İ", "а", " ", "c", "o", "m"]
    rng = random.Random(8812)
    for _ in range(20000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 20)))
        # No ':' or '/', and at most 20 characters, so no earlier classifier can claim the string.
        assert (detect_ioc_type(text) == "email") == bool(_MAIN_EMAIL_FULL.fullmatch(text)), repr(text)


@pytest.mark.parametrize(
    "build",
    [
        lambda n: "a" * n + "@" + "a." * n + "!",
        lambda n: "a@" + "-" * n,
        lambda n: "." * n + "@x.co",
        lambda n: "a@" + "aa." * n + "!",
    ],
    ids=["local_then_dotted_tail", "dash_domain", "leading_dots", "label_run"],
)
def test_detect_ioc_type_email_is_linear_on_adversarial_input(build) -> None:
    def cost(n: int) -> float:
        s = build(n)
        t = time.perf_counter()
        detect_ioc_type(s)
        return time.perf_counter() - t

    cost(2000)  # warm up
    big = cost(200_000)
    assert big < 5.0
