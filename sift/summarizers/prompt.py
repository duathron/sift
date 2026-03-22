"""Prompt construction utilities for LLM-backed summarizers.

Provides a reusable system prompt and a builder function that converts a
:class:`~sift.models.TriageReport` into a structured user prompt suitable for
submission to any chat-completion API (Anthropic, OpenAI, Ollama).
"""

from __future__ import annotations

import json

from sift.config import SummarizeConfig
from sift.models import TriageReport


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT: str = """\
You are a senior SOC analyst AI assistant specializing in alert triage and \
incident prioritization. Your role is to analyze structured security alert \
data and produce concise, actionable triage summaries for human analysts.

## Objectives
- Identify the most significant threats across alert clusters.
- Surface concrete, prioritized recommendations that analysts can act on \
  immediately.
- Be direct and technical — avoid filler language. Every sentence must convey \
  operational value.

## Output format
You MUST respond with a single valid JSON object and nothing else (no markdown \
fences, no prose outside the JSON). The object must conform exactly to the \
following schema:

{
  "executive_summary": "<string: 1-3 sentence cross-cluster summary>",
  "cluster_summaries": [
    {
      "cluster_id": "<string: cluster ID from input>",
      "narrative": "<string: 2-3 sentence technical narrative>",
      "recommendations": [
        {
          "action": "<string: specific, concrete action>",
          "priority": "<one of: IMMEDIATE | WITHIN_1H | WITHIN_24H | MONITOR>",
          "rationale": "<string: one-sentence justification>"
        }
      ]
    }
  ],
  "overall_priority": "<one of: NOISE | LOW | MEDIUM | HIGH | CRITICAL>"
}

## Guidance
- `executive_summary`: Summarize the overall threat landscape across all \
  clusters. State the total alert volume, the number of clusters, and the \
  highest observed priority. Highlight the most critical cluster if one exists.
- `cluster_summaries`: Include an entry for every non-NOISE cluster. The \
  narrative should describe what the grouped alerts represent, which assets \
  or users are involved, and the likely threat actor objective (if determinable).
- `recommendations`: Provide 1–3 recommendations per cluster, ordered by \
  decreasing urgency. Actions must be specific and operational (e.g., \
  "Block IP 203.0.113.42 at the edge firewall", not "investigate the IP").
- `overall_priority`: Set to the highest priority across all clusters; \
  use NOISE only if every cluster is NOISE.
- Do not invent data. Only reference information present in the input.
- Never include PII, raw credentials, or verbatim passwords in your output.
"""


# ---------------------------------------------------------------------------
# User prompt builder
# ---------------------------------------------------------------------------

def build_cluster_prompt(report: TriageReport, config: SummarizeConfig) -> str:
    """Build the user-turn prompt from *report*, respecting redaction rules.

    Constructs a structured natural-language + JSON-serializable prompt that
    describes the triage report for an LLM summarizer.  Fields listed in
    ``config.redact_fields`` are omitted from every alert representation to
    support data-minimization requirements before data leaves the perimeter.

    Args:
        report: The completed triage report containing clusters and alerts.
        config: The summarization configuration, used to determine which
            fields to redact via ``config.redact_fields``.

    Returns:
        A multi-section plain-text prompt string ready to be sent as the
        ``user`` message to any chat-completion API.
    """
    redact: set[str] = set(config.redact_fields)

    lines: list[str] = [
        "## Triage Report",
        f"- Total alerts ingested : {report.alerts_ingested}",
        f"- Alerts after dedup    : {report.alerts_after_dedup}",
        f"- Cluster count         : {len(report.clusters)}",
        "",
    ]

    # ------------------------------------------------------------------ #
    # Per-cluster details
    # ------------------------------------------------------------------ #
    for cluster in report.clusters:
        lines.append(f"### Cluster {cluster.id} — {cluster.label}")
        lines.append(f"- Priority    : {cluster.priority.value}")
        lines.append(f"- Score       : {cluster.score:.1f}")
        lines.append(f"- Alert count : {len(cluster.alerts)}")
        lines.append(f"- Reason      : {cluster.cluster_reason or 'unspecified'}")

        if cluster.first_seen or cluster.last_seen:
            first = cluster.first_seen.isoformat() if cluster.first_seen else "unknown"
            last = cluster.last_seen.isoformat() if cluster.last_seen else "unknown"
            lines.append(f"- Time range  : {first} → {last}")

        # IOCs
        if cluster.iocs and "iocs" not in redact:
            ioc_preview = cluster.iocs[:5]
            suffix = f" (+{len(cluster.iocs) - 5} more)" if len(cluster.iocs) > 5 else ""
            lines.append(f"- IOCs        : {', '.join(ioc_preview)}{suffix}")
        elif "iocs" in redact:
            lines.append("- IOCs        : [redacted]")
        else:
            lines.append("- IOCs        : none")

        # ATT&CK techniques
        if cluster.techniques:
            tech_strs = [
                f"{t.technique_id} ({t.technique_name}, {t.tactic})"
                for t in cluster.techniques
            ]
            lines.append(f"- Techniques  : {'; '.join(tech_strs)}")
        else:
            lines.append("- Techniques  : none mapped")

        # Sample alert titles (up to 5, respecting redaction)
        if cluster.alerts:
            lines.append("- Sample alerts:")
            for alert in cluster.alerts[:5]:
                parts: list[str] = []

                if "title" not in redact:
                    parts.append(f"[{alert.severity.value}] {alert.title}")
                else:
                    parts.append(f"[{alert.severity.value}] [title redacted]")

                optional_fields: list[tuple[str, str | None]] = [
                    ("source_ip", alert.source_ip),
                    ("dest_ip", alert.dest_ip),
                    ("user", alert.user),
                    ("host", alert.host),
                ]
                detail_parts: list[str] = []
                for field_name, field_val in optional_fields:
                    if field_val is None:
                        continue
                    if field_name in redact:
                        detail_parts.append(f"{field_name}=[redacted]")
                    else:
                        detail_parts.append(f"{field_name}={field_val}")

                if detail_parts:
                    parts.append(f"({', '.join(detail_parts)})")

                lines.append(f"  * {' '.join(parts)}")

            remaining = len(cluster.alerts) - 5
            if remaining > 0:
                lines.append(f"  * … and {remaining} more alert(s)")

        lines.append("")  # blank line between clusters

    # ------------------------------------------------------------------ #
    # Closing instruction
    # ------------------------------------------------------------------ #
    lines.append(
        "Based on the report above, produce the triage summary JSON as specified "
        "in the system prompt. Do not include any text outside the JSON object."
    )

    return "\n".join(lines)
