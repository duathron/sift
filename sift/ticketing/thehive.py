"""TheHive 5.x provider for sift ticketing."""

from __future__ import annotations

import httpx

from sift.pipeline.ioc_extractor import detect_ioc_type
from sift.ticketing.protocol import TicketDraft, TicketResult

_DEFAULT_TLP = 2   # AMBER
_DEFAULT_PAP = 2   # AMBER
_DEFAULT_TIMEOUT = 10.0


class TheHiveProvider:
    """Send sift TicketDrafts to TheHive 5 as Alerts.

    TheHive Alerts are the correct entry point: they represent unvalidated
    security events that an analyst can promote to a Case.  The sift summary
    and recommendations are embedded in the alert description as Markdown.
    """

    name = "thehive"

    def __init__(
        self,
        url: str,
        token: str,
        tlp: int = _DEFAULT_TLP,
        pap: int = _DEFAULT_PAP,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._base_url = url.rstrip("/")
        self._tlp = tlp
        self._pap = pap
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send(self, draft: TicketDraft) -> TicketResult:
        """Create a TheHive Alert from *draft* and return the result."""
        payload = self._build_payload(draft)
        response = self._client.post("/api/v1/alert", json=payload)
        response.raise_for_status()
        data = response.json()
        alert_id = data.get("_id", "")
        return TicketResult(
            provider=self.name,
            ticket_id=alert_id,
            ticket_url=f"{self._base_url}/alerts/{alert_id}/details" if alert_id else None,
            raw_response=data,
        )

    def healthcheck(self) -> tuple[bool, str]:
        """Return (True, login) if the API is reachable and token is valid."""
        try:
            r = self._client.get("/api/v1/user/current")
            r.raise_for_status()
            login = r.json().get("login", "unknown")
            return True, f"connected as {login}"
        except httpx.HTTPStatusError as e:
            return False, f"HTTP {e.response.status_code}: {e.response.text[:120]}"
        except httpx.RequestError as e:
            return False, str(e)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "TheHiveProvider":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_payload(self, draft: TicketDraft) -> dict:
        tags = (
            ["sift", f"severity:{draft.severity}", f"priority:{draft.priority}"]
            + ([f"hint:{draft.severity_hint}"] if draft.severity_hint else [])
            + [f"confidence:{int(draft.confidence * 100)}pct"]
            + draft.technique_ids[:10]
            + [cve for cve in draft.cve_ids[:5]]
            + [mid for mid in draft.mitre_ids[:5]]
        )
        observables = [
            {"dataType": self._ioc_type(ioc), "data": ioc}
            for ioc in draft.iocs
        ]
        return {
            "type": "sift-triage",
            "source": "sift",
            "sourceRef": f"sift-{draft.generated_at.strftime('%Y%m%dT%H%M%S')}-{draft.evidence.get('cluster_id', '')[:8]}",
            "title": draft.title,
            "description": self._render_markdown(draft),
            "severity": self._severity_int(draft.severity),
            "tlp": self._tlp,
            "pap": self._pap,
            "tags": tags,
            "observables": observables,
        }

    @staticmethod
    def _severity_int(severity: str) -> int:
        return {"INFO": 1, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity, 2)

    @staticmethod
    def _ioc_type(ioc: str) -> str:
        itype = detect_ioc_type(ioc)
        if itype == "ip":
            return "ip"
        if itype in ("hash_md5", "hash_sha1", "hash_sha256", "hash_sha512", "jarm", "ssdeep", "tlsh"):
            return "hash"
        if itype == "url":
            return "url"
        if itype == "email":
            return "mail"
        if itype in ("cve", "mitre_technique", "ps_encoded"):
            return "other"
        if itype == "registry_key":
            return "registry"
        if itype == "filename":
            return "filename"
        if itype == "domain":
            return "domain"
        return "other"

    @staticmethod
    def _render_markdown(draft: TicketDraft) -> str:
        lines: list[str] = [
            f"## Summary",
            "",
            draft.summary,
            "",
            f"**Severity:** {draft.severity} | **Priority:** {draft.priority} | **Confidence:** {draft.confidence:.0%}",
            "",
        ]

        if draft.timeline:
            lines += ["## Timeline", ""]
            lines += [f"- {entry}" for entry in draft.timeline]
            lines += [""]

        if draft.recommendations:
            lines += ["## Recommendations", ""]
            lines += [f"- [ ] {rec}" for rec in draft.recommendations]
            lines += [""]

        if draft.technique_ids:
            lines += ["## MITRE ATT&CK", ""]
            lines += [f"- {tid}" for tid in draft.technique_ids]
            lines += [""]

        if draft.source_file:
            lines += [f"*Source: {draft.source_file} — analyzed by sift {draft.sift_version}*"]
        else:
            lines += [f"*Analyzed by sift {draft.sift_version}*"]

        return "\n".join(lines)
