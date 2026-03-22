"""Tests for sift enrichment bridges: BarbBridge, VexBridge, EnrichmentRunner."""

from __future__ import annotations

import json
import subprocess
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sift.enrichers.barb_bridge import BarbBridge
from sift.enrichers.protocol import EnricherProtocol
from sift.enrichers.runner import EnrichmentMode, EnrichmentRunner
from sift.enrichers.vex_bridge import VexBridge
from sift.models import (
    Alert,
    AlertSeverity,
    Cluster,
    ClusterPriority,
    EnrichmentContext,
    TriageReport,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(iocs: list[str] | None = None) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        title="Test Alert",
        severity=AlertSeverity.HIGH,
        iocs=iocs or [],
    )


def make_cluster(iocs: list[str] | None = None) -> Cluster:
    alerts = [make_alert(iocs=iocs)]
    return Cluster(
        id=str(uuid.uuid4()),
        label="Test Cluster",
        alerts=alerts,
        priority=ClusterPriority.HIGH,
        score=10.0,
        iocs=iocs or [],
    )


def make_report(clusters: list[Cluster]) -> TriageReport:
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# EnricherProtocol conformance
# ---------------------------------------------------------------------------

class TestEnricherProtocolConformance:
    """BarbBridge and VexBridge satisfy the structural EnricherProtocol."""

    def test_barb_bridge_implements_enricher_protocol(self):
        assert isinstance(BarbBridge(), EnricherProtocol)

    def test_vex_bridge_implements_enricher_protocol(self):
        assert isinstance(VexBridge(), EnricherProtocol)


# ---------------------------------------------------------------------------
# BarbBridge.can_enrich
# ---------------------------------------------------------------------------

class TestBarbBridgeCanEnrich:
    """BarbBridge.can_enrich accepts URLs/domains and rejects IPs and hashes."""

    def test_http_url_returns_true(self):
        assert BarbBridge().can_enrich("http://evil.ru/login") is True

    def test_https_url_returns_true(self):
        assert BarbBridge().can_enrich("https://phish.com") is True

    def test_bare_domain_returns_true(self):
        assert BarbBridge().can_enrich("evil.ru") is True

    def test_ip_address_returns_false(self):
        assert BarbBridge().can_enrich("185.220.101.47") is False

    def test_md5_hash_returns_false(self):
        assert BarbBridge().can_enrich("d41d8cd98f00b204e9800998ecf8427e") is False

    def test_hxxp_defanged_url_returns_true(self):
        assert BarbBridge().can_enrich("hxxp://malware.example.com/payload") is True

    def test_hxxps_defanged_url_returns_true(self):
        assert BarbBridge().can_enrich("hxxps://phish.example.org/page") is True

    def test_sha256_hash_returns_false(self):
        sha256 = "a" * 64
        assert BarbBridge().can_enrich(sha256) is False


# ---------------------------------------------------------------------------
# VexBridge.can_enrich
# ---------------------------------------------------------------------------

class TestVexBridgeCanEnrich:
    """VexBridge.can_enrich accepts IPs, domains, URLs, hashes; not emails."""

    def test_ipv4_returns_true(self):
        assert VexBridge().can_enrich("185.220.101.47") is True

    def test_bare_domain_returns_true(self):
        assert VexBridge().can_enrich("evil.ru") is True

    def test_http_url_returns_true(self):
        assert VexBridge().can_enrich("http://evil.ru") is True

    def test_md5_hash_returns_true(self):
        assert VexBridge().can_enrich("d41d8cd98f00b204e9800998ecf8427e") is True

    def test_email_returns_false(self):
        assert VexBridge().can_enrich("user@evil.ru") is False

    def test_sha256_hash_returns_true(self):
        sha256 = "b" * 64
        assert VexBridge().can_enrich(sha256) is True

    def test_ipv6_returns_true(self):
        assert VexBridge().can_enrich("2001:db8::1") is True

    def test_email_with_ip_domain_returns_false(self):
        # Even if the domain part looks odd, '@' presence marks it as email
        assert VexBridge().can_enrich("admin@192.168.1.1") is False


# ---------------------------------------------------------------------------
# BarbBridge.enrich (mocked subprocess)
# ---------------------------------------------------------------------------

class TestBarbBridgeEnrich:
    """BarbBridge.enrich delegates to barb CLI and handles error cases."""

    def test_valid_json_response_included_in_results(self):
        barb_output = json.dumps({"ioc": "https://phish.com", "verdict": "PHISHING"})
        mock_result = MagicMock()
        mock_result.stdout = barb_output
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/barb"), \
             patch("subprocess.run", return_value=mock_result):
            bridge = BarbBridge()
            results = bridge.enrich(["https://phish.com"])

        assert len(results) == 1
        assert results[0]["verdict"] == "PHISHING"

    def test_barb_not_in_path_returns_error_dict(self):
        with patch("shutil.which", return_value=None):
            bridge = BarbBridge()
            results = bridge.enrich(["https://phish.com"])

        assert len(results) == 1
        assert "error" in results[0]

    def test_subprocess_timeout_returns_error_dict(self):
        with patch("shutil.which", return_value="/usr/bin/barb"), \
             patch(
                 "subprocess.run",
                 side_effect=subprocess.TimeoutExpired(cmd="barb", timeout=15),
             ):
            bridge = BarbBridge()
            results = bridge.enrich(["https://phish.com"])

        assert len(results) == 1
        assert "error" in results[0]
        assert "timed out" in results[0]["error"]

    def test_json_decode_error_returns_error_dict(self):
        mock_result = MagicMock()
        mock_result.stdout = "not valid json {"
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/barb"), \
             patch("subprocess.run", return_value=mock_result):
            bridge = BarbBridge()
            results = bridge.enrich(["https://phish.com"])

        assert len(results) == 1
        assert "error" in results[0]

    def test_empty_stdout_returns_error_dict(self):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = "barb crashed"

        with patch("shutil.which", return_value="/usr/bin/barb"), \
             patch("subprocess.run", return_value=mock_result):
            bridge = BarbBridge()
            results = bridge.enrich(["https://phish.com"])

        assert len(results) == 1
        assert "error" in results[0]

    def test_non_url_ioc_skipped_in_enrich(self):
        """IPs should not be passed to barb (filtered by can_enrich)."""
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"verdict": "SAFE"})
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/barb"), \
             patch("subprocess.run", return_value=mock_result) as mock_run:
            bridge = BarbBridge()
            results = bridge.enrich(["185.220.101.47"])

        # BarbBridge.enrich filters via can_enrich before calling CLI
        mock_run.assert_not_called()
        assert results == []


# ---------------------------------------------------------------------------
# VexBridge.enrich (mocked subprocess)
# ---------------------------------------------------------------------------

class TestVexBridgeEnrich:
    """VexBridge.enrich delegates to vex CLI and handles error cases."""

    def test_valid_json_response_included_in_results(self):
        vex_output = json.dumps({"ioc": "185.220.101.47", "verdict": "MALICIOUS"})
        mock_result = MagicMock()
        mock_result.stdout = vex_output
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/vex"), \
             patch("subprocess.run", return_value=mock_result):
            bridge = VexBridge()
            results = bridge.enrich(["185.220.101.47"])

        assert len(results) == 1
        assert results[0]["verdict"] == "MALICIOUS"

    def test_vex_not_in_path_returns_error_dict(self):
        with patch("shutil.which", return_value=None):
            bridge = VexBridge()
            results = bridge.enrich(["185.220.101.47"])

        assert len(results) == 1
        assert "error" in results[0]

    def test_vex_error_message_mentions_not_installed(self):
        with patch("shutil.which", return_value=None):
            bridge = VexBridge()
            results = bridge.enrich(["185.220.101.47"])

        assert "vex not installed" in results[0]["error"]

    def test_subprocess_timeout_returns_error_dict(self):
        with patch("shutil.which", return_value="/usr/bin/vex"), \
             patch(
                 "subprocess.run",
                 side_effect=subprocess.TimeoutExpired(cmd="vex", timeout=30),
             ):
            bridge = VexBridge()
            results = bridge.enrich(["185.220.101.47"])

        assert len(results) == 1
        assert "error" in results[0]
        assert "timed out" in results[0]["error"]


# ---------------------------------------------------------------------------
# EnrichmentRunner
# ---------------------------------------------------------------------------

class TestEnrichmentRunnerCollectIocs:
    """collect_iocs_from_report extracts unique IOCs across clusters."""

    def test_returns_unique_iocs_from_all_clusters(self):
        cluster_a = make_cluster(iocs=["185.220.101.47", "evil.ru"])
        cluster_b = make_cluster(iocs=["evil.ru", "d41d8cd98f00b204e9800998ecf8427e"])
        report = make_report([cluster_a, cluster_b])

        iocs = EnrichmentRunner.collect_iocs_from_report(report)

        # "evil.ru" appears in both clusters — should appear only once
        assert iocs.count("evil.ru") == 1
        assert "185.220.101.47" in iocs
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs

    def test_preserves_first_seen_order(self):
        cluster_a = make_cluster(iocs=["first.example.com", "second.example.com"])
        cluster_b = make_cluster(iocs=["third.example.com"])
        report = make_report([cluster_a, cluster_b])

        iocs = EnrichmentRunner.collect_iocs_from_report(report)

        assert iocs.index("first.example.com") < iocs.index("second.example.com")
        assert iocs.index("second.example.com") < iocs.index("third.example.com")

    def test_returns_empty_list_for_report_with_no_iocs(self):
        cluster = make_cluster(iocs=[])
        report = make_report([cluster])

        iocs = EnrichmentRunner.collect_iocs_from_report(report)

        assert iocs == []


class TestEnrichmentRunnerEnrich:
    """EnrichmentRunner.enrich orchestrates barb/vex correctly."""

    def test_max_iocs_limits_enriched_count(self):
        """Only the first max_iocs unique IOCs should be enriched."""
        iocs = [f"10.0.0.{i}" for i in range(10)]

        barb_mock = MagicMock(spec=BarbBridge)
        barb_mock.can_enrich.return_value = False
        vex_mock = MagicMock(spec=VexBridge)
        vex_mock.can_enrich.return_value = True
        vex_mock.enrich.return_value = [{"ioc": i, "verdict": "CLEAN"} for i in iocs[:2]]

        runner = EnrichmentRunner(mode=EnrichmentMode.VEX)
        runner.barb = barb_mock
        runner.vex = vex_mock

        runner.enrich(iocs, max_iocs=2)

        # vex.enrich should have been called with at most 2 IOCs
        called_iocs = vex_mock.enrich.call_args[0][0]
        assert len(called_iocs) <= 2

    def test_mode_barb_only_calls_barb_not_vex(self):
        barb_mock = MagicMock(spec=BarbBridge)
        barb_mock.can_enrich.return_value = True
        barb_mock.enrich.return_value = [{"ioc": "https://phish.com", "verdict": "PHISHING"}]
        vex_mock = MagicMock(spec=VexBridge)

        runner = EnrichmentRunner(mode=EnrichmentMode.BARB)
        runner.barb = barb_mock
        runner.vex = vex_mock

        runner.enrich(["https://phish.com"])

        barb_mock.enrich.assert_called_once()
        vex_mock.enrich.assert_not_called()

    def test_mode_vex_only_calls_vex_not_barb(self):
        barb_mock = MagicMock(spec=BarbBridge)
        vex_mock = MagicMock(spec=VexBridge)
        vex_mock.can_enrich.return_value = True
        vex_mock.enrich.return_value = [{"ioc": "185.220.101.47", "verdict": "CLEAN"}]

        runner = EnrichmentRunner(mode=EnrichmentMode.VEX)
        runner.barb = barb_mock
        runner.vex = vex_mock

        runner.enrich(["185.220.101.47"])

        vex_mock.enrich.assert_called_once()
        barb_mock.enrich.assert_not_called()

    def test_empty_ioc_list_returns_enrichment_context_with_empty_lists(self):
        runner = EnrichmentRunner(mode=EnrichmentMode.ALL)
        ctx = runner.enrich([])

        assert isinstance(ctx, EnrichmentContext)
        assert ctx.barb_results == []
        assert ctx.vex_results == []

    def test_returns_enrichment_context_instance(self):
        barb_mock = MagicMock(spec=BarbBridge)
        barb_mock.can_enrich.return_value = True
        barb_mock.enrich.return_value = []
        vex_mock = MagicMock(spec=VexBridge)
        vex_mock.can_enrich.return_value = True
        vex_mock.enrich.return_value = []

        runner = EnrichmentRunner(mode=EnrichmentMode.ALL)
        runner.barb = barb_mock
        runner.vex = vex_mock

        result = runner.enrich(["https://phish.com"])

        assert isinstance(result, EnrichmentContext)

    def test_duplicate_iocs_deduplicated_before_enrichment(self):
        vex_mock = MagicMock(spec=VexBridge)
        vex_mock.can_enrich.return_value = True
        vex_mock.enrich.return_value = []
        barb_mock = MagicMock(spec=BarbBridge)
        barb_mock.can_enrich.return_value = False

        runner = EnrichmentRunner(mode=EnrichmentMode.VEX)
        runner.barb = barb_mock
        runner.vex = vex_mock

        runner.enrich(["185.220.101.47", "185.220.101.47", "185.220.101.47"])

        called_iocs = vex_mock.enrich.call_args[0][0]
        assert len(called_iocs) == 1

    def test_mode_all_calls_both_barb_and_vex(self):
        barb_mock = MagicMock(spec=BarbBridge)
        barb_mock.can_enrich.return_value = True
        barb_mock.enrich.return_value = []
        vex_mock = MagicMock(spec=VexBridge)
        vex_mock.can_enrich.return_value = True
        vex_mock.enrich.return_value = []

        runner = EnrichmentRunner(mode=EnrichmentMode.ALL)
        runner.barb = barb_mock
        runner.vex = vex_mock

        runner.enrich(["https://phish.com"])

        barb_mock.enrich.assert_called_once()
        vex_mock.enrich.assert_called_once()


# ---------------------------------------------------------------------------
# EnrichmentContext model defaults
# ---------------------------------------------------------------------------

class TestEnrichmentContextModel:
    """EnrichmentContext Pydantic model default values."""

    def test_barb_results_defaults_to_empty_list(self):
        ctx = EnrichmentContext()
        assert ctx.barb_results == []

    def test_vex_results_defaults_to_empty_list(self):
        ctx = EnrichmentContext()
        assert ctx.vex_results == []

    def test_barb_results_accepts_list_of_dicts(self):
        data = [{"ioc": "https://phish.com", "verdict": "PHISHING"}]
        ctx = EnrichmentContext(barb_results=data)
        assert ctx.barb_results == data

    def test_vex_results_accepts_list_of_dicts(self):
        data = [{"ioc": "185.220.101.47", "verdict": "MALICIOUS"}]
        ctx = EnrichmentContext(vex_results=data)
        assert ctx.vex_results == data
