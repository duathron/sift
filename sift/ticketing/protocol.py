"""Ticketing protocol, data models, and provider interface for sift."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class TicketDraft(BaseModel):
    """Provider-agnostic ticket — mapped to provider payload on send."""

    title: str
    summary: str
    severity: str                                    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    priority: str                                    # IMMEDIATE | WITHIN_1H | WITHIN_24H | MONITOR
    confidence: float = Field(ge=0.0, le=1.0)
    timeline: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)
    source_file: str | None = None
    generated_at: datetime
    sift_version: str


class TicketResult(BaseModel):
    """Return value from TicketProvider.send()."""

    provider: str
    ticket_id: str | None = None
    ticket_url: str | None = None
    raw_response: dict = Field(default_factory=dict)


@runtime_checkable
class TicketProvider(Protocol):
    """Protocol every concrete provider must satisfy."""

    name: str

    def send(self, draft: TicketDraft) -> TicketResult: ...

    def healthcheck(self) -> tuple[bool, str]: ...
