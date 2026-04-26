"""Jira Service Management provider for sift ticketing."""

from __future__ import annotations

from base64 import b64encode

import httpx

from sift.ticketing.protocol import TicketDraft, TicketResult

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_ISSUE_TYPE = "Task"


# ---------------------------------------------------------------------------
# Minimal Atlassian Document Format (ADF) builder
# ---------------------------------------------------------------------------

def _text(content: str) -> dict:
    return {"type": "text", "text": content}


def _heading(level: int, content: str) -> dict:
    return {
        "type": "heading",
        "attrs": {"level": level},
        "content": [_text(content)],
    }


def _paragraph(*parts: str) -> dict:
    return {
        "type": "paragraph",
        "content": [_text(p) for p in parts],
    }


def _bullet_list(items: list[str]) -> dict:
    return {
        "type": "bulletList",
        "content": [
            {
                "type": "listItem",
                "content": [_paragraph(item)],
            }
            for item in items
        ],
    }


def _task_list(items: list[str]) -> dict:
    """Checklist-style list for recommendations."""
    return {
        "type": "taskList",
        "attrs": {"localId": "task-list-1"},
        "content": [
            {
                "type": "taskItem",
                "attrs": {"localId": f"task-{i}", "state": "TODO"},
                "content": [_text(item)],
            }
            for i, item in enumerate(items)
        ],
    }


def _rule() -> dict:
    return {"type": "rule"}


def _build_adf(draft: TicketDraft) -> dict:
    """Build a minimal ADF document from a TicketDraft."""
    content: list[dict] = []

    content.append(_heading(2, "Summary"))
    content.append(_paragraph(draft.summary))
    content.append(_paragraph(
        f"Severity: {draft.severity}  |  "
        f"Priority: {draft.priority}  |  "
        f"Confidence: {draft.confidence:.0%}"
    ))

    if draft.timeline:
        content.append(_rule())
        content.append(_heading(2, "Timeline"))
        content.append(_bullet_list(draft.timeline))

    if draft.recommendations:
        content.append(_rule())
        content.append(_heading(2, "Recommendations"))
        content.append(_task_list(draft.recommendations))

    if draft.iocs:
        content.append(_rule())
        content.append(_heading(2, "Indicators of Compromise"))
        content.append(_bullet_list(draft.iocs))

    if draft.technique_ids:
        content.append(_rule())
        content.append(_heading(2, "MITRE ATT&CK"))
        content.append(_bullet_list(draft.technique_ids))

    content.append(_rule())
    footer = f"Analyzed by sift {draft.sift_version}"
    if draft.source_file:
        footer += f"  |  Source: {draft.source_file}"
    content.append(_paragraph(footer))

    return {"version": 1, "type": "doc", "content": content}


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

class JiraProvider:
    """Send sift TicketDrafts to Jira Service Management as Issues.

    Authentication: Basic Auth (email + API token) as required by Jira Cloud.
    Description body: Atlassian Document Format (ADF) JSON.
    """

    name = "jira"

    def __init__(
        self,
        url: str,
        email: str,
        token: str,
        project_key: str,
        issue_type: str = _DEFAULT_ISSUE_TYPE,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._base_url = url.rstrip("/")
        self._project_key = project_key
        self._issue_type = issue_type
        _creds = b64encode(f"{email}:{token}".encode()).decode()
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Basic {_creds}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send(self, draft: TicketDraft) -> TicketResult:
        """Create a Jira issue from *draft* and return the result."""
        payload = self._build_payload(draft)
        response = self._client.post("/rest/api/3/issue", json=payload)
        response.raise_for_status()
        data = response.json()
        key = data.get("key", "")
        return TicketResult(
            provider=self.name,
            ticket_id=key,
            ticket_url=f"{self._base_url}/browse/{key}" if key else None,
            raw_response=data,
        )

    def healthcheck(self) -> tuple[bool, str]:
        """Return (True, email) if the API is reachable and credentials are valid."""
        try:
            r = self._client.get("/rest/api/3/myself")
            r.raise_for_status()
            email = r.json().get("emailAddress", "unknown")
            return True, f"connected as {email}"
        except httpx.HTTPStatusError as e:
            return False, f"HTTP {e.response.status_code}: {e.response.text[:120]}"
        except httpx.RequestError as e:
            return False, str(e)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "JiraProvider":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_payload(self, draft: TicketDraft) -> dict:
        labels = (
            ["sift", f"sift-{draft.severity.lower()}", f"confidence-{int(draft.confidence * 100)}"]
            + [t.replace(".", "-") for t in draft.technique_ids[:5]]
        )
        return {
            "fields": {
                "project": {"key": self._project_key},
                "issuetype": {"name": self._issue_type},
                "summary": draft.title,
                "description": _build_adf(draft),
                "priority": {"name": self._priority_name(draft.severity)},
                "labels": labels,
            }
        }

    @staticmethod
    def _priority_name(severity: str) -> str:
        return {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Lowest",
        }.get(severity, "Medium")
