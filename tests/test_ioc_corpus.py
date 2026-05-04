"""Golden-file regression tests for the IOC extractor (v1.1.10+).

Each fixture under ``tests/fixtures/ioc_corpus/`` represents a real-world
SOC artefact (Sysmon CSV row, OTX pulse, ransomware note, sandbox report,
defanged threat-intel writeup). The tests assert that *required* IOCs
appear in the extractor output and that *forbidden* values do not.

These tests document the contract between sift and downstream consumers.
Adding a new IOC type means adding a new fixture + assertion here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sift.pipeline.ioc_extractor import (
    classify_severity_hint,
    detect_ioc_type,
    extract_iocs,
)

CORPUS_DIR = Path(__file__).parent / "fixtures" / "ioc_corpus"


def _read(name: str) -> str:
    return (CORPUS_DIR / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 01 — PS Eclipse Sysmon CSV row
# ---------------------------------------------------------------------------

class TestPSEclipseSysmon:
    """The original v1.1.08 motivating bug: filename + null-hash filter."""

    @pytest.fixture
    def iocs(self):
        return extract_iocs(_read("01_ps_eclipse_sysmon.txt"))

    def test_real_filename_extracted(self, iocs):
        assert "OUTSTANDING_GUTTER.exe" in iocs

    def test_powershell_script_extracted(self, iocs):
        assert "script.ps1" in iocs

    def test_real_sha1_extracted(self, iocs):
        assert "93f3c96ad1306e1701835a677b289c5d96081709" in iocs

    def test_real_md5_extracted(self, iocs):
        assert "a1b2c3d4e5f67890a1b2c3d4e5f67890" in iocs

    def test_real_sha256_extracted(self, iocs):
        assert (
            "deadbeefcafef00d1234567890abcdef0123456789abcdef0123456789abcdef"
            in iocs
        )

    def test_null_imphash_filtered(self, iocs):
        assert "00000000000000000000000000000000" not in iocs

    def test_public_ip_extracted(self, iocs):
        assert "3.22.30.40" in iocs

    def test_powershell_encoded_block_extracted(self, iocs):
        assert any(i.startswith("ps_encoded:") for i in iocs)


# ---------------------------------------------------------------------------
# 02 — Defanged threat report
# ---------------------------------------------------------------------------

class TestDefangedThreatReport:
    """Refang preprocessor — hxxp://, [.], [dot], [at], fullwidth."""

    @pytest.fixture
    def iocs(self):
        return extract_iocs(_read("02_defanged_threat_report.txt"))

    def test_hxxp_refanged_to_url(self, iocs):
        assert "https://evil.com/gate.php" in iocs

    def test_bracket_dot_refanged_to_domain(self, iocs):
        assert "evil.com" in iocs

    def test_word_dot_refanged(self, iocs):
        assert "malicious.example-c2.net" in iocs

    def test_at_dot_refanged_to_email(self, iocs):
        assert "attacker@phish.tld" in iocs

    def test_paren_dot_refanged(self, iocs):
        assert "payload-server.evil.com" in iocs

    def test_fullwidth_dot_refanged(self, iocs):
        assert "badactor.com" in iocs

    def test_fullwidth_at_refanged(self, iocs):
        assert "bad@domain.com" in iocs

    def test_defanged_ipv4_refanged(self, iocs):
        # 8.8.8.8 is public DNS — should be extracted after refang.
        assert "8.8.8.8" in iocs
        assert "198.51.100.42" in iocs

    def test_tunnel_domain_extracted(self, iocs):
        assert "payload-abc123.ngrok.io" in iocs

    def test_paste_url_extracted(self, iocs):
        assert any("pastebin.com" in i for i in iocs)

    def test_cves_extracted(self, iocs):
        assert "CVE-2024-3400" in iocs
        assert "CVE-2023-23397" in iocs

    def test_mitre_techniques_extracted(self, iocs):
        for t in ("T1059.001", "T1190", "T1566.001", "T1071.001"):
            assert t in iocs, f"missing {t}"


# ---------------------------------------------------------------------------
# 03 — any.run sandbox report
# ---------------------------------------------------------------------------

class TestAnyRunReport:
    """Sandbox-style detonation: registry, JA3/JA3S, JARM, ssdeep, TLSH."""

    @pytest.fixture
    def iocs(self):
        return extract_iocs(_read("03_anyrun_report.txt"))

    def test_registry_run_key_extracted(self, iocs):
        assert any(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in i
            for i in iocs
        )

    def test_registry_service_imagepath_extracted(self, iocs):
        assert any(r"HKLM\SYSTEM\CurrentControlSet\Services" in i for i in iocs)

    def test_powershell_encoded_extracted(self, iocs):
        assert any(i.startswith("ps_encoded:") for i in iocs)

    def test_discord_webhook_url_extracted(self, iocs):
        assert any(
            "discord.com/api/webhooks" in i for i in iocs if i.startswith("http")
        )

    def test_trycloudflare_tunnel_extracted(self, iocs):
        assert any(".trycloudflare.com" in i for i in iocs)

    def test_ja3_extracted_keyed(self, iocs):
        assert "e7d705a3286e19ea42f587b344ee6865" in iocs

    def test_ja3s_extracted_keyed(self, iocs):
        assert "4835b19f14997673071435cb321f5445" in iocs

    def test_jarm_extracted(self, iocs):
        # 62 hex chars
        assert any(len(i) == 62 and all(c in "0123456789abcdef" for c in i)
                   for i in iocs)

    def test_ssdeep_extracted(self, iocs):
        assert any(":" in i and i.split(":", 1)[0] == "1536" for i in iocs)

    def test_tlsh_extracted(self, iocs):
        assert any(i.upper().startswith("T1") and len(i) >= 70 for i in iocs)

    def test_severity_hint_for_run_key(self, iocs):
        run_keys = [i for i in iocs if "\\Run\\" in i.replace("/", "\\")]
        assert run_keys, "expected at least one Run-key registry IOC"
        assert classify_severity_hint(run_keys[0]) == "high"

    def test_severity_hint_for_tunnel_domain(self):
        assert classify_severity_hint("abc123.ngrok.io") == "high"
        assert classify_severity_hint(
            "https://abc.trycloudflare.com/x"
        ) == "high"

    def test_severity_hint_for_discord_webhook(self):
        assert classify_severity_hint(
            "https://discord.com/api/webhooks/123/abc"
        ) == "high"

    def test_severity_hint_for_ps_encoded(self):
        assert classify_severity_hint("ps_encoded:" + "A" * 120) == "critical"


# ---------------------------------------------------------------------------
# 04 — OTX pulse
# ---------------------------------------------------------------------------

class TestOTXPulse:
    """Threat-intel pulse with defanged IOCs + ATT&CK + CVE all in one doc."""

    @pytest.fixture
    def iocs(self):
        return extract_iocs(_read("04_otx_pulse.txt"))

    def test_ipv4_extracted(self, iocs):
        assert "103.124.106.237" in iocs
        assert "175.45.178.224" in iocs

    def test_ipv6_cloudflare_extracted(self, iocs):
        assert "2606:4700:4700::1111" in iocs

    def test_domains_extracted(self, iocs):
        for d in ("movie-asia.com", "secsupport.net", "update-service.online"):
            assert d in iocs, f"missing {d}"

    def test_url_extracted(self, iocs):
        assert any("movie-asia.com/script.aspx" in i for i in iocs)

    def test_md5_extracted(self, iocs):
        assert "a4d25f10c81a956b0fd3b8bbb3aaeed1" in iocs

    def test_sha1_extracted(self, iocs):
        assert "0d11d8e63f7ab9d0eb83f5a93b1c0e0e7b6c4f93" in iocs

    def test_sha256_extracted(self, iocs):
        assert (
            "7f0fbfae39e62ac8e8d21f72ddd3fbe9e9b9b2cf04c7b2e95e17bb3be9b6bab8"
            in iocs
        )

    def test_email_extracted(self, iocs):
        assert "hr-recruit@careers-aerospace.net" in iocs

    def test_attachment_filename_extracted(self, iocs):
        assert "JobDescription.docm" in iocs

    def test_cve_extracted(self, iocs):
        assert "CVE-2025-12345" in iocs

    def test_mitre_techniques_extracted(self, iocs):
        for t in ("T1566.001", "T1204.002", "T1059.005", "T1547.001"):
            assert t in iocs, f"missing {t}"


# ---------------------------------------------------------------------------
# 05 — Ransomware note (refanged email + filename)
# ---------------------------------------------------------------------------

class TestRansomwareNote:
    """Verifies SHA256 + email + executable name extraction in a ransom note."""

    @pytest.fixture
    def iocs(self):
        return extract_iocs(_read("05_ransomware_ransomnote.txt"))

    def test_sha256_extracted(self, iocs):
        assert (
            "cafebabe1234567890deadbeefabcdef1234567890fedcba0987654321feedfa"
            in iocs
        )

    def test_encryptor_executable_extracted(self, iocs):
        assert "ENCRYPTOR.exe" in iocs

    def test_email_extracted(self, iocs):
        # Note: protonmail.com domain, defanged in source
        assert "ransom-decoder@protonmail.com" in iocs


# ---------------------------------------------------------------------------
# Type-detection regression
# ---------------------------------------------------------------------------

class TestDetectIOCType:
    @pytest.mark.parametrize(
        "ioc,expected",
        [
            ("CVE-2024-3400", "cve"),
            ("T1059.001", "mitre_technique"),
            ("T1190", "mitre_technique"),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "registry_key"),
            ("ps_encoded:" + "A" * 100, "ps_encoded"),
            ("a" * 128, "hash_sha512"),
            ("a" * 62, "jarm"),
            ("1536:y6dkO/ZD3OgK2bUk:y6mO/ZDHZk", "ssdeep"),
            ("evil.com", "domain"),
            ("https://evil.com/x", "url"),
            ("user@evil.com", "email"),
            ("OUTSTANDING_GUTTER.exe", "filename"),
            ("3.22.30.40", "ip"),
        ],
    )
    def test_detect_type(self, ioc, expected):
        assert detect_ioc_type(ioc) == expected

    def test_null_hash_returns_unknown(self):
        # Sentinel hashes should not be classified as a real hash type.
        assert detect_ioc_type("0" * 32) == "unknown"
        assert detect_ioc_type("f" * 64) == "unknown"

    def test_empty_string_hashes_returns_unknown(self):
        # Hashes-of-empty-bytestring sentinels are also dropped.
        # MD5(""), SHA1(""), SHA256("") respectively.
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "unknown"
        assert detect_ioc_type(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ) == "unknown"
        assert detect_ioc_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == "unknown"


# ---------------------------------------------------------------------------
# Negative tests — false-positive prevention
# ---------------------------------------------------------------------------

class TestNegatives:
    """Things that look IOC-shaped but should NOT be extracted."""

    def test_at_in_prose_not_refanged(self):
        # ``state[at]rest`` is common in security prose; must not become
        # ``state@rest``.
        iocs = extract_iocs("Encryption: data is at state[at]rest only")
        assert all("@" not in i for i in iocs)
        assert "state@rest" not in iocs

    def test_array_index_at_not_refanged(self):
        iocs = extract_iocs("loop iteration: array[at]index throws")
        assert all("@" not in i for i in iocs)

    def test_at_with_domain_context_is_refanged(self):
        iocs = extract_iocs("Reach me at user[at]example[dot]com please")
        assert "user@example.com" in iocs

    def test_mitre_t2024_not_extracted(self):
        # Range-restricted to T1xxx, so `T2024 model` no longer matches.
        iocs = extract_iocs("Intel T2024 chip variant")
        assert "T2024" not in iocs

    def test_mitre_t9999_not_extracted(self):
        iocs = extract_iocs("ticket id T9999 closed")
        assert "T9999" not in iocs

    def test_real_t1059_extracted(self):
        iocs = extract_iocs("ATT&CK: T1059 detected")
        assert "T1059" in iocs

    def test_url_trailing_period_stripped(self):
        iocs = extract_iocs("Visit https://evil.com/x.")
        assert "https://evil.com/x" in iocs
        assert "https://evil.com/x." not in iocs

    def test_url_trailing_paren_stripped(self):
        iocs = extract_iocs("Beacon (https://evil.com/c2) detected")
        assert "https://evil.com/c2" in iocs

    def test_timestamp_not_classified_as_ssdeep_in_bridge(self):
        # 12:34:56 timestamps must not look like ssdeep to the bridge filter.
        from sift.enrichers.vex_bridge import _is_non_enrichable_type
        assert _is_non_enrichable_type("12:34:56") is False

    def test_real_ssdeep_classified_as_ssdeep_in_bridge(self):
        from sift.enrichers.vex_bridge import _is_non_enrichable_type
        assert _is_non_enrichable_type(
            "1536:y6dkO/ZD3OgK2bUk:y6mO/ZDHZk"
        ) is True

    def test_ipv6_does_not_explode_on_long_input(self):
        # Catastrophic-backtracking guard. Should return promptly.
        import time

        adversarial = "aaaa:" * 50 + "not_hex_x"
        start = time.monotonic()
        iocs = extract_iocs(adversarial)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"IPv6 regex took {elapsed:.2f}s — backtracking?"
        # Result correctness is secondary — we mostly care that it's bounded.
        del iocs

    def test_empty_input(self):
        assert extract_iocs("") == []
        assert extract_iocs("   \n\t  ") == []

    def test_whitespace_only_returns_empty(self):
        assert extract_iocs("\n\n\n") == []


# ---------------------------------------------------------------------------
# Severity-hint coverage
# ---------------------------------------------------------------------------

class TestSeverityHintCoverage:
    """Verify ``classify_severity_hint`` returns ``None`` for benign types."""

    def test_plain_ip_no_hint(self):
        assert classify_severity_hint("8.8.8.8") is None

    def test_plain_domain_no_hint(self):
        assert classify_severity_hint("example.com") is None

    def test_md5_no_hint(self):
        assert classify_severity_hint("5d41402abc4b2a76b9719d911017c592") is None

    def test_cve_no_hint(self):
        assert classify_severity_hint("CVE-2024-3400") is None

    def test_mitre_no_hint(self):
        assert classify_severity_hint("T1059.001") is None

    def test_pastebin_url_high(self):
        assert classify_severity_hint(
            "https://pastebin.com/raw/Xy12AbCd"
        ) == "high"

    def test_telegram_bot_url_high(self):
        assert classify_severity_hint(
            "https://api.telegram.org/bot1234567:abc/sendMessage"
        ) == "high"

    def test_non_persistence_regkey_no_hint(self):
        assert classify_severity_hint(
            r"HKLM\SOFTWARE\Microsoft\Office\Common\Settings"
        ) is None

    def test_run_key_lowercase_high(self):
        assert classify_severity_hint(
            r"hklm\software\microsoft\windows\currentversion\run\evil"
        ) == "high"


# ---------------------------------------------------------------------------
# Refang idempotence
# ---------------------------------------------------------------------------

class TestRefangIdempotence:
    """Refang twice = refang once (no further substitutions kick in)."""

    @pytest.mark.parametrize(
        "text",
        [
            "hxxps://evil[.]com",
            "user[at]phish[dot]tld",
            "8[.]8[.]8[.]8",
            "evil．com / mail＠domain．com",
            "state[at]rest is fine",   # negative case (no refang at all)
            "",
        ],
    )
    def test_refang_idempotent(self, text):
        from sift.pipeline.ioc_extractor import _refang
        once = _refang(text)
        twice = _refang(once)
        assert once == twice


# ---------------------------------------------------------------------------
# Boundary tests
# ---------------------------------------------------------------------------

class TestBoundaries:
    def test_cve_seven_digit_suffix(self):
        iocs = extract_iocs("see CVE-2024-1234567 advisory")
        assert "CVE-2024-1234567" in iocs

    def test_cve_minimum_four_digit_suffix(self):
        iocs = extract_iocs("see CVE-2024-1234 advisory")
        assert "CVE-2024-1234" in iocs

    def test_jarm_uppercase_extracted(self):
        # 62 hex chars uppercase
        upper = "2AD2AD0002AD2AD00042D42D000000ABCDEF1234567890ABCDEF1234567890"
        iocs = extract_iocs(f"JARM={upper}")
        assert upper.lower() in iocs or upper in iocs

    def test_tlsh_seventy_chars(self):
        tlsh = "T1" + "A" * 70
        iocs = extract_iocs(f"tlsh={tlsh}")
        assert any(i.upper().startswith("T1") and len(i) >= 70 for i in iocs)
