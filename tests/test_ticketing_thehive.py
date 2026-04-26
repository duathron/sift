"""Tests for TheHiveProvider using pytest-httpx."""

from datetime import datetime, timezone

import pytest

from sift.ticketing.protocol import TicketDraft, TicketProvider
from sift.ticketing.thehive import TheHiveProvider

_BASE = "https://thehive.example.com"


def _draft(**kwargs) -> TicketDraft:
    defaults = dict(
        title="[sift] CRITICAL | Credential Dumping + Lateral Movement",
        summary="Attack chain on dc01: brute force → credential dump → lateral movement.",
        severity="CRITICAL",
        priority="IMMEDIATE",
        confidence=0.95,
        iocs=["185.220.101.47", "10.10.1.5"],
        technique_ids=["T1003", "T1021.001"],
        recommendations=["Isolate dc01", "Reset svc_admin"],
        timeline=["[2026-04-20 10:00:00 UTC] [CRITICAL] Credential Dumping Detected"],
        evidence={"cluster_id": "abc12345-dead-beef-1234-abcdef012345"},
        source_file="alerts.json",
        generated_at=datetime(2026, 4, 20, 10, 0, 0, tzinfo=timezone.utc),
        sift_version="1.1.0",
    )
    return TicketDraft(**(defaults | kwargs))


def _provider(tlp: int = 2) -> TheHiveProvider:
    return TheHiveProvider(url=_BASE, token="TESTTOKEN", tlp=tlp)


class TestTheHiveProvider:
    def test_name(self):
        assert TheHiveProvider.name == "thehive"

    def test_satisfies_protocol(self):
        assert isinstance(_provider(), TicketProvider)

    def test_send_creates_alert(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{_BASE}/api/v1/alert",
            method="POST",
            json={"_id": "~123456789", "title": "[sift] CRITICAL | ..."},
        )
        result = _provider().send(_draft())
        assert result.provider == "thehive"
        assert result.ticket_id == "~123456789"

    def test_send_url_contains_alert_id(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{_BASE}/api/v1/alert",
            method="POST",
            json={"_id": "~42"},
        )
        result = _provider().send(_draft())
        assert result.ticket_url == f"{_BASE}/alerts/~42/details"

    def test_send_payload_title(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider().send(_draft(title="[sift] HIGH | Test"))
        request = httpx_mock.get_requests()[0]
        import json
        body = json.loads(request.content)
        assert body["title"] == "[sift] HIGH | Test"

    def test_send_payload_severity_critical(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider().send(_draft(severity="CRITICAL"))
        import json
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["severity"] == 4

    def test_send_payload_includes_observables(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider().send(_draft(iocs=["1.2.3.4", "evil.com"]))
        import json
        body = json.loads(httpx_mock.get_requests()[0].content)
        observable_data = [o["data"] for o in body["observables"]]
        assert "1.2.3.4" in observable_data
        assert "evil.com" in observable_data

    def test_send_payload_tlp_default(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider(tlp=3).send(_draft())
        import json
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["tlp"] == 3

    def test_send_payload_tags_include_sift(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider().send(_draft())
        import json
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert "sift" in body["tags"]

    def test_send_payload_tags_include_technique_ids(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider().send(_draft(technique_ids=["T1003", "T1021.001"]))
        import json
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert "T1003" in body["tags"]

    def test_send_payload_source_ref_format(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider().send(_draft())
        import json
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["sourceRef"].startswith("sift-20260420T")

    def test_send_description_contains_summary(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider().send(_draft(summary="Specific summary text."))
        import json
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert "Specific summary text." in body["description"]

    def test_send_description_contains_recommendations(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/api/v1/alert", method="POST", json={"_id": "x"})
        _provider().send(_draft(recommendations=["Isolate dc01"]))
        import json
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert "Isolate dc01" in body["description"]
        assert "- [ ]" in body["description"]

    def test_http_error_raises(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{_BASE}/api/v1/alert", method="POST", status_code=401
        )
        import httpx
        with pytest.raises(httpx.HTTPStatusError):
            _provider().send(_draft())

    def test_healthcheck_success(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{_BASE}/api/v1/user/current",
            json={"login": "analyst@soc.example.com"},
        )
        ok, msg = _provider().healthcheck()
        assert ok is True
        assert "analyst@soc.example.com" in msg

    def test_healthcheck_401(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{_BASE}/api/v1/user/current", status_code=401, text="Unauthorized"
        )
        ok, msg = _provider().healthcheck()
        assert ok is False
        assert "401" in msg

    def test_healthcheck_connection_error(self, httpx_mock):
        import httpx as _httpx
        httpx_mock.add_exception(
            _httpx.ConnectError("Connection refused"),
            url=f"{_BASE}/api/v1/user/current",
        )
        ok, msg = _provider().healthcheck()
        assert ok is False
        assert msg


class TestTheHiveIocType:
    def test_ipv4(self):
        assert TheHiveProvider._ioc_type("192.168.1.1") == "ip"

    def test_md5_hash(self):
        assert TheHiveProvider._ioc_type("a" * 32) == "hash"

    def test_sha1_hash(self):
        assert TheHiveProvider._ioc_type("a" * 40) == "hash"

    def test_sha256_hash(self):
        assert TheHiveProvider._ioc_type("a" * 64) == "hash"

    def test_https_url(self):
        assert TheHiveProvider._ioc_type("https://evil.com/payload") == "url"

    def test_domain(self):
        assert TheHiveProvider._ioc_type("evil.phish.ru") == "domain"

    def test_plain_hostname(self):
        assert TheHiveProvider._ioc_type("badhost") == "domain"


class TestTheHiveSeverityInt:
    def test_critical(self):
        assert TheHiveProvider._severity_int("CRITICAL") == 4

    def test_high(self):
        assert TheHiveProvider._severity_int("HIGH") == 3

    def test_medium(self):
        assert TheHiveProvider._severity_int("MEDIUM") == 2

    def test_low(self):
        assert TheHiveProvider._severity_int("LOW") == 1

    def test_info(self):
        assert TheHiveProvider._severity_int("INFO") == 1

    def test_unknown_defaults_medium(self):
        assert TheHiveProvider._severity_int("UNKNOWN") == 2
