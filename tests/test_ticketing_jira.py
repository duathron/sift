"""Tests for JiraProvider and ADF builder using pytest-httpx."""

import json
from datetime import datetime, timezone

import pytest

from sift.ticketing.jira import JiraProvider, _build_adf, _bullet_list, _heading, _paragraph, _task_list
from sift.ticketing.protocol import TicketDraft, TicketProvider

_BASE = "https://company.atlassian.net"


def _draft(**kwargs) -> TicketDraft:
    defaults = dict(
        title="[sift] HIGH | SSH Brute Force + Account Lockout",
        summary="SSH brute force from 185.220.101.47 followed by account lockout on dc01.",
        severity="HIGH",
        priority="WITHIN_1H",
        confidence=0.80,
        iocs=["185.220.101.47"],
        technique_ids=["T1110.001"],
        recommendations=["Block 185.220.101.47", "Reset jdoe credentials"],
        timeline=["[2026-04-20 10:00:00 UTC] [HIGH] SSH Brute Force Detected"],
        evidence={"cluster_id": "abc12345-0000-0000-0000-abcdef012345"},
        source_file="alerts.csv",
        generated_at=datetime(2026, 4, 20, 10, 0, 0, tzinfo=timezone.utc),
        sift_version="1.1.0",
    )
    return TicketDraft(**(defaults | kwargs))


def _provider(**kwargs) -> JiraProvider:
    defaults = dict(
        url=_BASE,
        email="analyst@company.com",
        token="JIRATOKEN123",
        project_key="SOC",
    )
    return JiraProvider(**(defaults | kwargs))


class TestJiraProvider:
    def test_name(self):
        assert JiraProvider.name == "jira"

    def test_satisfies_protocol(self):
        assert isinstance(_provider(), TicketProvider)

    def test_send_creates_issue(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{_BASE}/rest/api/3/issue",
            method="POST",
            json={"id": "10001", "key": "SOC-42", "self": f"{_BASE}/rest/api/3/issue/10001"},
        )
        result = _provider().send(_draft())
        assert result.provider == "jira"
        assert result.ticket_id == "SOC-42"

    def test_send_url_contains_key(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{_BASE}/rest/api/3/issue", method="POST",
            json={"id": "10001", "key": "SOC-42", "self": ""},
        )
        result = _provider().send(_draft())
        assert result.ticket_url == f"{_BASE}/browse/SOC-42"

    def test_send_payload_project_key(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider(project_key="SECOPS").send(_draft())
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["fields"]["project"]["key"] == "SECOPS"

    def test_send_payload_summary(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider().send(_draft(title="[sift] CRITICAL | Test"))
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["fields"]["summary"] == "[sift] CRITICAL | Test"

    def test_send_payload_priority_critical(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider().send(_draft(severity="CRITICAL"))
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["fields"]["priority"]["name"] == "Highest"

    def test_send_payload_priority_high(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider().send(_draft(severity="HIGH"))
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["fields"]["priority"]["name"] == "High"

    def test_send_payload_labels_contain_sift(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider().send(_draft())
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert "sift" in body["fields"]["labels"]

    def test_send_payload_labels_contain_technique(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider().send(_draft(technique_ids=["T1003"]))
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert "T1003" in body["fields"]["labels"]

    def test_send_payload_description_is_adf(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider().send(_draft())
        body = json.loads(httpx_mock.get_requests()[0].content)
        desc = body["fields"]["description"]
        assert desc["type"] == "doc"
        assert desc["version"] == 1
        assert isinstance(desc["content"], list)

    def test_send_issue_type_default(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider().send(_draft())
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["fields"]["issuetype"]["name"] == "Task"

    def test_send_issue_type_custom(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                json={"id": "1", "key": "SOC-1", "self": ""})
        _provider(issue_type="Incident").send(_draft())
        body = json.loads(httpx_mock.get_requests()[0].content)
        assert body["fields"]["issuetype"]["name"] == "Incident"

    def test_http_error_raises(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/issue", method="POST",
                                status_code=403)
        import httpx as _httpx
        with pytest.raises(_httpx.HTTPStatusError):
            _provider().send(_draft())

    def test_healthcheck_success(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{_BASE}/rest/api/3/myself",
            json={"emailAddress": "analyst@company.com", "displayName": "SOC Analyst"},
        )
        ok, msg = _provider().healthcheck()
        assert ok is True
        assert "analyst@company.com" in msg

    def test_healthcheck_401(self, httpx_mock):
        httpx_mock.add_response(url=f"{_BASE}/rest/api/3/myself", status_code=401,
                                text="Unauthorized")
        ok, msg = _provider().healthcheck()
        assert ok is False
        assert "401" in msg

    def test_healthcheck_connection_error(self, httpx_mock):
        import httpx as _httpx
        httpx_mock.add_exception(
            _httpx.ConnectError("refused"),
            url=f"{_BASE}/rest/api/3/myself",
        )
        ok, msg = _provider().healthcheck()
        assert ok is False


class TestJiraPriorityName:
    def test_critical(self):
        assert JiraProvider._priority_name("CRITICAL") == "Highest"

    def test_high(self):
        assert JiraProvider._priority_name("HIGH") == "High"

    def test_medium(self):
        assert JiraProvider._priority_name("MEDIUM") == "Medium"

    def test_low(self):
        assert JiraProvider._priority_name("LOW") == "Low"

    def test_info(self):
        assert JiraProvider._priority_name("INFO") == "Lowest"

    def test_unknown_defaults_medium(self):
        assert JiraProvider._priority_name("UNKNOWN") == "Medium"


class TestAdfBuilder:
    def test_doc_structure(self):
        draft = _draft()
        adf = _build_adf(draft)
        assert adf["type"] == "doc"
        assert adf["version"] == 1
        assert len(adf["content"]) > 0

    def test_summary_heading_present(self):
        adf = _build_adf(_draft())
        headings = [n for n in adf["content"] if n["type"] == "heading"]
        heading_texts = [h["content"][0]["text"] for h in headings]
        assert "Summary" in heading_texts

    def test_summary_text_in_body(self):
        adf = _build_adf(_draft(summary="Unique summary ABC."))
        all_text = json.dumps(adf)
        assert "Unique summary ABC." in all_text

    def test_recommendations_section_present(self):
        adf = _build_adf(_draft(recommendations=["Do this"]))
        all_text = json.dumps(adf)
        assert "Recommendations" in all_text
        assert "Do this" in all_text

    def test_ioc_section_present(self):
        adf = _build_adf(_draft(iocs=["192.168.1.1"]))
        all_text = json.dumps(adf)
        assert "192.168.1.1" in all_text

    def test_timeline_section_present(self):
        adf = _build_adf(_draft(timeline=["[10:00] [HIGH] event"]))
        all_text = json.dumps(adf)
        assert "[10:00] [HIGH] event" in all_text

    def test_technique_ids_in_body(self):
        adf = _build_adf(_draft(technique_ids=["T1003", "T1021.001"]))
        all_text = json.dumps(adf)
        assert "T1003" in all_text
        assert "T1021.001" in all_text

    def test_footer_contains_sift_version(self):
        adf = _build_adf(_draft(sift_version="1.1.0"))
        all_text = json.dumps(adf)
        assert "sift 1.1.0" in all_text

    def test_footer_contains_source_file(self):
        adf = _build_adf(_draft(source_file="my_alerts.json"))
        all_text = json.dumps(adf)
        assert "my_alerts.json" in all_text

    def test_heading_node(self):
        h = _heading(2, "Test")
        assert h["type"] == "heading"
        assert h["attrs"]["level"] == 2
        assert h["content"][0]["text"] == "Test"

    def test_bullet_list_node(self):
        bl = _bullet_list(["item1", "item2"])
        assert bl["type"] == "bulletList"
        assert len(bl["content"]) == 2

    def test_task_list_state_todo(self):
        tl = _task_list(["fix this", "check that"])
        items = tl["content"]
        assert all(item["attrs"]["state"] == "TODO" for item in items)
