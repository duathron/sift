"""Pydantic v2 data models for sift."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Alert severity
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    """Severity level of a single alert (from SIEM or normalized)."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score(self) -> int:
        """Numeric score used in cluster priority calculation."""
        return {"INFO": 1, "LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 20}[self.value]


# ---------------------------------------------------------------------------
# Raw / normalized alert
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """A single normalized alert from any SIEM source."""

    id: str
    timestamp: Optional[datetime] = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    title: str
    description: Optional[str] = None
    source: Optional[str] = None          # sensor / detection source name
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    category: Optional[str] = None       # e.g. "Malware", "Phishing", "Lateral Movement"
    iocs: list[str] = Field(default_factory=list)          # extracted IOCs (IPs, hashes, URLs, domains)
    technique_ids: list[str] = Field(default_factory=list) # ATT&CK technique IDs
    raw: dict = Field(default_factory=dict)                # original untouched record
    _duplicate_of: Optional[str] = None  # set during deduplication


# ---------------------------------------------------------------------------
# Cluster priority / verdict
# ---------------------------------------------------------------------------

class ClusterPriority(str, Enum):
    """Priority level of a cluster of related alerts."""

    NOISE = "NOISE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def exit_code(self) -> int:
        """Exit code contribution: critical/high → 1, else 0."""
        return 1 if self in (ClusterPriority.CRITICAL, ClusterPriority.HIGH) else 0

    @property
    def icon(self) -> str:
        return {
            "NOISE": "·",
            "LOW": "↓",
            "MEDIUM": "~",
            "HIGH": "↑",
            "CRITICAL": "!",
        }[self.value]


# ---------------------------------------------------------------------------
# ATT&CK mapping
# ---------------------------------------------------------------------------

class TechniqueRef(BaseModel):
    """Reference to a MITRE ATT&CK technique."""

    technique_id: str    # e.g. T1566.001
    technique_name: str  # e.g. Spearphishing Attachment
    tactic: str          # e.g. Initial Access


# ---------------------------------------------------------------------------
# Cluster
# ---------------------------------------------------------------------------

class Cluster(BaseModel):
    """A group of related alerts with a computed priority."""

    id: str
    label: str                                              # short human-readable label
    alerts: list[Alert]
    priority: ClusterPriority
    score: float                                            # sum of alert severity scores
    confidence: float = 1.0                                 # clustering confidence [0.0–1.0]
    techniques: list[TechniqueRef] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)          # all unique IOCs across alerts
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    cluster_reason: str = ""                               # why alerts were grouped


# ---------------------------------------------------------------------------
# Summary (LLM or template output)
# ---------------------------------------------------------------------------

class Recommendation(BaseModel):
    """A concrete, actionable recommendation for a SOC analyst."""

    action: str           # e.g. "Block IP 10.0.0.5 at perimeter firewall"
    priority: str         # IMMEDIATE | WITHIN_1H | WITHIN_24H | MONITOR
    rationale: str        # one-sentence reason


class ClusterSummary(BaseModel):
    """AI or template-generated summary for a single cluster."""

    cluster_id: str
    narrative: str                                                # 2-3 sentences
    recommendations: list[Recommendation] = Field(default_factory=list)


class SummaryResult(BaseModel):
    """Full AI-generated triage summary."""

    executive_summary: str
    cluster_summaries: list[ClusterSummary] = Field(default_factory=list)
    overall_priority: ClusterPriority
    provider: str   # anthropic | openai | ollama | template
    generated_at: datetime


# ---------------------------------------------------------------------------
# Enrichment context (barb / vex output)
# ---------------------------------------------------------------------------

class EnrichmentContext(BaseModel):
    """Optional enrichment data from barb and/or vex."""

    barb_results: list[dict] = Field(default_factory=list)   # barb AnalysisResult dicts
    vex_results: list[dict] = Field(default_factory=list)    # vex TriageResult dicts


# ---------------------------------------------------------------------------
# Final triage report
# ---------------------------------------------------------------------------

class PipelineManifest(BaseModel):
    """Records which tools were involved in producing this report."""

    sift_version: str
    barb_version: Optional[str] = None
    vex_version: Optional[str] = None
    input_format: str
    enrich_mode: Optional[str] = None  # "library" | "local" | None


class TriageReport(BaseModel):
    """The complete triage report — primary output of sift."""

    input_file: Optional[str] = None
    alerts_ingested: int
    alerts_after_dedup: int
    clusters: list[Cluster]
    summary: Optional[SummaryResult] = None
    enrichment: Optional[EnrichmentContext] = None
    manifest: Optional[PipelineManifest] = None
    analyzed_at: datetime

    @property
    def has_critical(self) -> bool:
        return any(c.priority == ClusterPriority.CRITICAL for c in self.clusters)

    @property
    def exit_code(self) -> int:
        """0 = no high/critical clusters, 1 = high/critical found, 2 = error."""
        return 1 if any(c.priority.exit_code == 1 for c in self.clusters) else 0
