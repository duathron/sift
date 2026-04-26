"""sift ticketing — create incident tickets from triage results.

Providers: thehive | jira | dry-run
"""

from __future__ import annotations

from pathlib import Path

from sift.ticketing.dry_run import DryRunProvider
from sift.ticketing.mapper import report_to_draft, top_clusters_for_ticket
from sift.ticketing.protocol import TicketDraft, TicketProvider, TicketResult

__all__ = [
    "TicketDraft",
    "TicketProvider",
    "TicketResult",
    "DryRunProvider",
    "build_provider",
    "report_to_draft",
    "top_clusters_for_ticket",
]


def build_provider(
    name: str,
    cfg,  # AppConfig — imported lazily to avoid circular imports
    output_path: Path | None = None,
) -> TicketProvider:
    """Instantiate the named ticket provider with credentials from *cfg* and env."""
    import os

    if name == "dry-run":
        return DryRunProvider(output_path=output_path)

    if name == "thehive":
        from sift.ticketing.thehive import TheHiveProvider

        token = os.getenv("SIFT_THEHIVE_TOKEN", "")
        if not token:
            raise ValueError(
                "SIFT_THEHIVE_TOKEN not set — run: sift config --ticket-token <token>"
            )
        url = getattr(cfg.ticketing, "url", None)
        if not url:
            raise ValueError(
                "ticketing.url not configured — run: sift config --ticket-url https://..."
            )
        timeout = getattr(cfg.ticketing, "timeout", 10.0)
        return TheHiveProvider(url=url, token=token, timeout=timeout)

    if name == "jira":
        from sift.ticketing.jira import JiraProvider

        token = os.getenv("SIFT_JIRA_TOKEN", "")
        email = os.getenv("SIFT_JIRA_EMAIL", "") or getattr(cfg.ticketing, "jira_email", "")
        url = getattr(cfg.ticketing, "url", None)
        project_key = getattr(cfg.ticketing, "project_key", None)
        issue_type = getattr(cfg.ticketing, "jira_issue_type", "Task")
        timeout = getattr(cfg.ticketing, "timeout", 10.0)
        missing = [k for k, v in [("token", token), ("email", email), ("url", url), ("project_key", project_key)] if not v]
        if missing:
            raise ValueError(
                f"Jira config incomplete — missing: {', '.join(missing)}. "
                "Run: sift config --ticket-url ... --ticket-project ... --ticket-jira-email ..."
            )
        return JiraProvider(
            url=url,
            email=email,
            token=token,
            project_key=project_key,
            issue_type=issue_type,
            timeout=timeout,
        )

    raise ValueError(
        f"Unknown ticket provider: {name!r}. Valid: thehive | jira | dry-run"
    )
