"""Prompt construction utilities for LLM-backed summarizers.

Provides provider-specific system prompts, few-shot examples, and builder functions
that convert a :class:`~sift.models.TriageReport` into a structured user prompt
suitable for submission to any chat-completion API (Anthropic, OpenAI, Ollama).
"""

from __future__ import annotations

import logging

from pydantic import BaseModel

from sift.config import SummarizeConfig
from sift.models import TriageReport
from sift.summarizers.injection_detector import PromptInjectionDetector

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic Models for Few-Shot Examples
# ---------------------------------------------------------------------------

class PromptExample(BaseModel):
    """A single few-shot example for in-context learning."""

    input: str = "Input prompt or partial report"
    output: str = "Expected JSON output"


# ---------------------------------------------------------------------------
# Base System Prompts
# ---------------------------------------------------------------------------

_BASE_SYSTEM_PROMPT: str = """\
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

# Use the base prompt as the template/default
SYSTEM_PROMPT: str = _BASE_SYSTEM_PROMPT

# Provider-specific system prompts
SYSTEM_PROMPTS: dict[str, str] = {
    "template": _BASE_SYSTEM_PROMPT,
    "anthropic": _BASE_SYSTEM_PROMPT + """\

## Additional guidance for Claude
- Use your understanding of SOC workflows to inform narrative structure.
- Prioritize clarity and actionability in recommendations.
- If cluster data is ambiguous, state assumptions clearly in recommendations.
- Leverage JSON schema validation to ensure output compliance.
""",
    "openai": _BASE_SYSTEM_PROMPT + """\

## Additional guidance for GPT
- Structure recommendations as discrete, implementable steps.
- Use explicit priority escalation: IMMEDIATE > WITHIN_1H > WITHIN_24H > MONITOR.
- Ensure all fields are populated; use placeholder strings if data is insufficient.
- Validate JSON compliance before output completion.
""",
    "ollama": _BASE_SYSTEM_PROMPT + """\

## Additional guidance for local models
- Keep narratives concise (< 100 tokens per summary).
- Use explicit, concrete language over abstractions.
- Minimize reasoning chains; focus on direct recommendations.
- All output must be valid JSON with no escaping issues.
""",
}

# Provider-specific few-shot examples
PROVIDER_EXAMPLES: dict[str, list[PromptExample]] = {
    "template": [
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 5\n- Alerts after dedup    : 4\n- Cluster count         : 1\n\n### Cluster abc123 — Malware Detection\n- Priority    : HIGH\n- Score       : 75.0\n- Alert count : 4\n- Reason      : hash match\n- IOCs        : sha256:abc123, sha256:def456\n- Techniques  : T1566.001 (Spearphishing Attachment, Initial Access)",
            output='{"executive_summary":"Processed 5 alerts (4 after deduplication), grouped into 1 cluster. 1 malware cluster requires immediate attention.","cluster_summaries":[{"cluster_id":"abc123","narrative":"4 HIGH alert(s) grouped by hash match. Involves 2 IOC(s) including sha256:abc123. ATT&CK: T1566.001.","recommendations":[{"action":"Block hash sha256:abc123 at email gateway","priority":"IMMEDIATE","rationale":"High-confidence malware detection on initial access vector."},{"action":"Scan affected mailboxes for variants","priority":"WITHIN_1H","rationale":"Spearphishing attachment may have multiple variants."}]}],"overall_priority":"HIGH"}',
        ),
    ],
    "anthropic": [
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 3\n- Alerts after dedup    : 3\n- Cluster count         : 1\n\n### Cluster xyz789 — Suspicious Login\n- Priority    : CRITICAL\n- Score       : 95.0\n- Alert count : 3\n- Reason      : source ip + user combination\n- IOCs        : 203.0.113.15\n- Techniques  : T1078.003 (Valid Accounts, Defense Evasion)\n- Sample alerts:\n  * [CRITICAL] Impossible travel detected (source_ip=203.0.113.15, user=jdoe)",
            output='{"executive_summary":"Processed 3 alerts (3 after deduplication), grouped into 1 cluster. 1 critical cluster requires immediate action. Suspicious login from foreign IP with impossible travel timeline.","cluster_summaries":[{"cluster_id":"xyz789","narrative":"3 CRITICAL alert(s) grouped by source IP and user combination. Impossible travel detected for user jdoe from IP 203.0.113.15. ATT&CK: T1078.003 (Valid Accounts).","recommendations":[{"action":"Isolate affected user account and force password reset","priority":"IMMEDIATE","rationale":"Critical-priority cluster with impossible travel pattern indicates account compromise."},{"action":"Block source IP 203.0.113.15 at perimeter firewall","priority":"IMMEDIATE","rationale":"Prevent lateral movement or data exfiltration from hostile source."},{"action":"Review user jdoe login history for past 48 hours","priority":"WITHIN_1H","rationale":"Determine scope and timeline of potential compromise."}]}],"overall_priority":"CRITICAL"}',
        ),
    ],
    "openai": [
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 2\n- Alerts after dedup    : 2\n- Cluster count         : 1\n\n### Cluster sec456 — C2 Communication\n- Priority    : MEDIUM\n- Score       : 50.0\n- Alert count : 2\n- Reason      : dest domain\n- IOCs        : evil.example.com\n- Techniques  : T1071.001 (Application Layer Protocol, Command and Control)\n- Sample alerts:\n  * [MEDIUM] DNS query to suspicious domain (dest_ip=evil.example.com)",
            output='{"executive_summary":"Processed 2 alerts (2 after deduplication), grouped into 1 cluster. Suspected C2 communication to external domain warrants investigation.","cluster_summaries":[{"cluster_id":"sec456","narrative":"2 MEDIUM alert(s) grouped by destination domain. Multiple DNS queries to evil.example.com detected. ATT&CK: T1071.001 (Application Layer Protocol).","recommendations":[{"action":"Block domain evil.example.com at DNS resolver","priority":"WITHIN_24H","rationale":"Prevent command and control communication while investigation proceeds."},{"action":"Review network logs for data exfiltration to evil.example.com","priority":"WITHIN_1H","rationale":"Confirm scope of potential C2 communication."}]}],"overall_priority":"MEDIUM"}',
        ),
    ],
    "ollama": [
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 1\n- Alerts after dedup    : 1\n- Cluster count         : 1\n\n### Cluster abc111 — Phishing\n- Priority    : LOW\n- Score       : 20.0\n- Alert count : 1\n- Reason      : subject line\n- IOCs        : none\n- Techniques  : none mapped",
            output='{"executive_summary":"Processed 1 alert (1 after deduplication), grouped into 1 cluster. Low-confidence phishing detection.","cluster_summaries":[{"cluster_id":"abc111","narrative":"1 LOW alert(s) grouped by subject line match. No IOCs or ATT&CK mapping.","recommendations":[{"action":"Monitor for escalation","priority":"MONITOR","rationale":"Low-confidence cluster; re-evaluate if additional alerts arrive."}]}],"overall_priority":"LOW"}',
        ),
    ],
}


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def get_system_prompt(provider: str) -> str:
    """Get the system prompt for a specific provider.

    Falls back to the template/base prompt if the provider is unknown.

    Args:
        provider: Provider identifier (e.g. "anthropic", "openai", "ollama", "template").

    Returns:
        The provider-specific system prompt string.
    """
    return SYSTEM_PROMPTS.get(provider, SYSTEM_PROMPTS["template"])


def get_provider_examples(provider: str) -> list[PromptExample]:
    """Get few-shot examples for a specific provider.

    Args:
        provider: Provider identifier (e.g. "anthropic", "openai", "ollama", "template").

    Returns:
        A list of :class:`PromptExample` objects (may be empty if provider unknown).
    """
    return PROVIDER_EXAMPLES.get(provider, [])


def build_cluster_prompt_with_examples(
    report: TriageReport,
    config: SummarizeConfig,
    provider: str = "template",
) -> str:
    """Build the user-turn prompt with optional few-shot examples.

    Constructs a structured prompt that includes the triage report and
    optionally prepends provider-specific few-shot examples.

    Args:
        report: The completed triage report containing clusters and alerts.
        config: The summarization configuration.
        provider: Provider identifier for example selection. Defaults to "template".

    Returns:
        A multi-section plain-text prompt string with examples and report.
    """
    examples = get_provider_examples(provider)

    lines: list[str] = []

    # Prepend few-shot examples if available
    if examples:
        lines.append("## Few-Shot Examples\n")
        for i, ex in enumerate(examples, 1):
            lines.append(f"### Example {i}")
            lines.append("Input:")
            lines.append(ex.input)
            lines.append("\nOutput:")
            lines.append(ex.output)
            lines.append("")

    # Append the main report prompt
    lines.append(build_cluster_prompt(report, config))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# User prompt builder
# ---------------------------------------------------------------------------

def build_cluster_prompt(report: TriageReport, config: SummarizeConfig) -> str:
    """Build the user-turn prompt from *report*, respecting redaction rules.

    Constructs a structured natural-language + JSON-serializable prompt that
    describes the triage report for an LLM summarizer.  Fields listed in
    ``config.redact_fields`` are omitted from every alert representation to
    support data-minimization requirements before data leaves the perimeter.

    Includes prompt injection detection to scan alert content for suspicious
    patterns before LLM submission. Findings are logged as warnings but do not
    block processing (non-blocking security scanning).

    Args:
        report: The completed triage report containing clusters and alerts.
        config: The summarization configuration, used to determine which
            fields to redact via ``config.redact_fields``.

    Returns:
        A multi-section plain-text prompt string ready to be sent as the
        ``user`` message to any chat-completion API.
    """
    # Scan alerts for injection patterns and redact suspicious fields.
    # Honour operator-defined whitelist_patterns from PromptInjectionConfig
    # (passed via the parent AppConfig → injected into SummarizeConfig callers).
    whitelist = getattr(config, "_injection_whitelist", None) or []
    detector = PromptInjectionDetector(whitelist_patterns=whitelist)
    safe_clusters = []
    for cluster in report.clusters:
        safe_alerts = []
        for alert in cluster.alerts:
            findings = detector.detect(alert)
            if findings:
                logger.warning(
                    f"Injection pattern(s) detected in alert {alert.id}: "
                    f"{', '.join(f.pattern_type for f in findings)} (severity: "
                    f"{', '.join(str(f.severity.value) for f in findings)}) — redacting"
                )
                alert = detector.redact_alert(alert, findings)
            safe_alerts.append(alert)
        safe_cluster = cluster.model_copy(update={"alerts": safe_alerts})
        safe_clusters.append(safe_cluster)
    report = report.model_copy(update={"clusters": safe_clusters})

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
