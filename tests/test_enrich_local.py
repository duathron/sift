"""Tests for local heuristic enrichment (--enrich-mode local)."""

from __future__ import annotations

import pytest

from sift.enrichers.local_heuristics import analyze
from sift.enrichers.runner import EnrichmentMode, EnrichmentRunner


# ---------------------------------------------------------------------------
# EnrichmentMode enum
# ---------------------------------------------------------------------------

class TestEnrichmentModeEnum:
    def test_local_mode_enum_value(self):
        assert EnrichmentMode.LOCAL.value == "local"

    def test_all_modes_present(self):
        values = {m.value for m in EnrichmentMode}
        assert {"all", "barb", "vex", "local"} == values


# ---------------------------------------------------------------------------
# IP address heuristics
# ---------------------------------------------------------------------------

class TestIPHeuristics:
    def test_private_ipv4_detected(self):
        result = analyze("192.168.1.1")
        assert "ip:private" in result["findings"]

    def test_loopback_detected(self):
        result = analyze("127.0.0.1")
        assert "ip:loopback" in result["findings"]

    def test_public_ip_no_private_flag(self):
        result = analyze("8.8.8.8")
        assert "ip:private" not in result["findings"]
        assert "ip:ipv4" in result["findings"]

    def test_ipv6_classified(self):
        result = analyze("2001:db8::1")
        assert "ip:ipv6" in result["findings"]


# ---------------------------------------------------------------------------
# URL / domain heuristics
# ---------------------------------------------------------------------------

class TestDomainHeuristics:
    def test_suspicious_tld_detected(self):
        result = analyze("evil.tk")
        assert any("suspicious_tld" in f for f in result["findings"])

    def test_normal_tld_clean(self):
        result = analyze("microsoft.com")
        assert not any("suspicious_tld" in f for f in result["findings"])

    def test_ip_in_url_detected(self):
        result = analyze("http://192.168.1.1/login")
        assert "url:ip_in_url" in result["findings"]

    def test_suspicious_keyword_in_domain(self):
        result = analyze("secure-login.xyz")
        assert any("suspicious_keyword" in f for f in result["findings"])

    def test_clean_domain_no_suspicious_keyword(self):
        result = analyze("github.com")
        assert not any("suspicious_keyword" in f for f in result["findings"])


# ---------------------------------------------------------------------------
# High-entropy (DGA) detection
# ---------------------------------------------------------------------------

class TestEntropyHeuristics:
    def test_high_entropy_domain(self):
        # 16 unique chars → Shannon entropy ≈ 4.0 bits > 3.8 threshold
        result = analyze("qzxvjkfmpwrtybcd.com")
        assert "domain:high_entropy" in result["findings"]

    def test_low_entropy_domain_clean(self):
        result = analyze("microsoft.com")
        assert "domain:high_entropy" not in result["findings"]


# ---------------------------------------------------------------------------
# Hash identification
# ---------------------------------------------------------------------------

class TestHashHeuristics:
    def test_md5_identified(self):
        result = analyze("d41d8cd98f00b204e9800998ecf8427e")
        assert "hash:md5" in result["findings"]

    def test_sha256_identified(self):
        result = analyze("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert "hash:sha256" in result["findings"]


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

class TestResultStructure:
    def test_result_has_required_keys(self):
        result = analyze("8.8.8.8")
        assert "ioc" in result
        assert "source" in result
        assert "findings" in result

    def test_source_is_local_heuristics(self):
        result = analyze("8.8.8.8")
        assert result["source"] == "local_heuristics"


# ---------------------------------------------------------------------------
# EnrichmentRunner LOCAL mode
# ---------------------------------------------------------------------------

class TestEnrichmentRunnerLocal:
    def test_local_mode_returns_enrichment_context(self):
        runner = EnrichmentRunner(mode=EnrichmentMode.LOCAL)
        ctx = runner.enrich(["8.8.8.8", "evil.tk"])
        assert ctx is not None
        assert isinstance(ctx.barb_results, list)
        assert len(ctx.barb_results) == 2

    def test_local_mode_respects_max_iocs(self):
        iocs = [f"10.0.0.{i}" for i in range(30)]
        runner = EnrichmentRunner(mode=EnrichmentMode.LOCAL)
        ctx = runner.enrich(iocs, max_iocs=5)
        assert len(ctx.barb_results) == 5

    def test_local_mode_no_vex_results(self):
        runner = EnrichmentRunner(mode=EnrichmentMode.LOCAL)
        ctx = runner.enrich(["8.8.8.8"])
        assert ctx.vex_results == []
