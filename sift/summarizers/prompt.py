"""Prompt construction utilities for LLM-backed summarizers.

Provides provider-specific system prompts, few-shot examples, and builder functions
that convert a :class:`~sift.models.TriageReport` into a structured user prompt
suitable for submission to any chat-completion API (Anthropic, OpenAI, Ollama).
"""

from __future__ import annotations

import base64
import hashlib
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

## IOC types
The following IOC type labels may appear in cluster IOC lists:
- ``ip`` — public IP address (network indicator)
- ``domain`` — fully-qualified domain name
- ``url`` — full URL including scheme
- ``email`` — email address (phishing / BEC indicator)
- ``hash_md5`` / ``hash_sha1`` / ``hash_sha256`` / ``hash_sha512`` — file hashes
- ``ssdeep`` / ``tlsh`` / ``jarm`` — fuzzy / TLS fingerprints
- ``filename`` — Windows executable or script (e.g. OUTSTANDING_GUTTER.exe)
- ``cve`` — CVE identifier → indicates known vulnerability exploitation; \
  recommend patching / virtual patching
- ``mitre_technique`` — MITRE ATT&CK technique ID (T1xxx) → maps kill-chain stage
- ``registry_key`` — Windows registry path → indicates persistence mechanism
- ``ps_encoded`` — PowerShell encoded command (base64 stub) → \
  deobfuscation needed; high-confidence malicious execution
- ``tunnel`` / ``paste`` host domains → potential exfiltration or C2 abuse

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
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 2\n- Alerts after dedup    : 2\n- Cluster count         : 1\n\n### Cluster p1tmpl — Phishing Chain with New IOC Types\n- Priority    : CRITICAL\n- Score       : 140.0\n- Alert count : 2\n- Reason      : shared IOC overlap\n- IOCs        : CVE-2024-3400, T1566.001, HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater, ps_encoded:a1b2c3d4e5f6a7b8 (320b)\n- Techniques  : T1566.001 (Spearphishing Attachment, Initial Access); T1547.001 (Registry Run Keys, Persistence)",
            output='{"executive_summary":"Processed 2 alerts (2 after deduplication), grouped into 1 cluster. Active exploitation of CVE-2024-3400 with PowerShell obfuscation and registry persistence.","cluster_summaries":[{"cluster_id":"p1tmpl","narrative":"2 CRITICAL alert(s) grouped by shared IOCs. CVE-2024-3400 exploitation (T1566.001) followed by encoded PowerShell execution and persistence via HKCU Run key (T1547.001). Encoded payload requires deobfuscation.","recommendations":[{"action":"Isolate affected endpoints immediately and capture memory","priority":"IMMEDIATE","rationale":"Active exploitation with obfuscated execution and confirmed persistence indicates hands-on-keyboard attacker."},{"action":"Remove registry key HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater on all affected hosts","priority":"IMMEDIATE","rationale":"Persistence mechanism must be cleared before re-imaging to prevent reinfection."},{"action":"Apply CVE-2024-3400 patch or virtual patch at WAF layer","priority":"WITHIN_1H","rationale":"Unpatched systems remain vulnerable to re-exploitation."},{"action":"Decode and analyze PowerShell payload to identify second-stage artifacts","priority":"WITHIN_1H","rationale":"Encoded commands may drop additional malware or establish C2 not yet visible in logs."}]}],"overall_priority":"CRITICAL"}',
        ),
    ],
    "anthropic": [
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 3\n- Alerts after dedup    : 3\n- Cluster count         : 1\n\n### Cluster xyz789 — Suspicious Login\n- Priority    : CRITICAL\n- Score       : 95.0\n- Alert count : 3\n- Reason      : source ip + user combination\n- IOCs        : 203.0.113.15\n- Techniques  : T1078.003 (Valid Accounts, Defense Evasion)\n- Sample alerts:\n  * [CRITICAL] Impossible travel detected (source_ip=203.0.113.15, user=jdoe)",
            output='{"executive_summary":"Processed 3 alerts (3 after deduplication), grouped into 1 cluster. 1 critical cluster requires immediate action. Suspicious login from foreign IP with impossible travel timeline.","cluster_summaries":[{"cluster_id":"xyz789","narrative":"3 CRITICAL alert(s) grouped by source IP and user combination. Impossible travel detected for user jdoe from IP 203.0.113.15. ATT&CK: T1078.003 (Valid Accounts).","recommendations":[{"action":"Isolate affected user account and force password reset","priority":"IMMEDIATE","rationale":"Critical-priority cluster with impossible travel pattern indicates account compromise."},{"action":"Block source IP 203.0.113.15 at perimeter firewall","priority":"IMMEDIATE","rationale":"Prevent lateral movement or data exfiltration from hostile source."},{"action":"Review user jdoe login history for past 48 hours","priority":"WITHIN_1H","rationale":"Determine scope and timeline of potential compromise."}]}],"overall_priority":"CRITICAL"}',
        ),
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 2\n- Alerts after dedup    : 2\n- Cluster count         : 1\n\n### Cluster p1ant — Phishing Chain with New IOC Types\n- Priority    : CRITICAL\n- Score       : 168.0\n- Alert count : 2\n- Reason      : shared IOC overlap (CVE + ps_encoded + registry + MITRE)\n- IOCs        : CVE-2024-3400, T1566.001, HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater, ps_encoded:a1b2c3d4e5f6a7b8 (320b), https://abc123.ngrok.io/c2\n- Techniques  : T1566.001 (Spearphishing Attachment, Initial Access); T1547.001 (Registry Run Keys, Persistence); T1059.001 (PowerShell, Execution)",
            output='{"executive_summary":"Processed 2 alerts (2 after deduplication), grouped into 1 cluster. CRITICAL phishing chain: CVE-2024-3400 exploitation, obfuscated PowerShell execution, registry persistence, and ngrok C2 tunnel all active simultaneously.","cluster_summaries":[{"cluster_id":"p1ant","narrative":"2 CRITICAL alert(s) correlating CVE-2024-3400 initial access (T1566.001) with encoded PowerShell execution (T1059.001) and HKCU Run-key persistence (T1547.001). C2 via ngrok tunnel (abc123.ngrok.io) confirms active attacker presence. The ps_encoded stub must be fully decoded to reveal secondary payload.","recommendations":[{"action":"Isolate all affected endpoints and block ngrok.io at perimeter immediately","priority":"IMMEDIATE","rationale":"Active C2 channel via ngrok confirms attacker has interactive access; containment prevents lateral movement."},{"action":"Purge registry persistence key HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater on all affected hosts","priority":"IMMEDIATE","rationale":"Persistence survives reboot; removal required before re-imaging."},{"action":"Decode the ps_encoded payload in a sandboxed environment to identify second-stage malware and C2 infrastructure","priority":"WITHIN_1H","rationale":"Full payload analysis may reveal additional IOCs not yet visible in detection telemetry."},{"action":"Deploy emergency patch or virtual patch for CVE-2024-3400 across all internet-facing assets","priority":"WITHIN_1H","rationale":"Unpatched systems remain initial-access targets."}]}],"overall_priority":"CRITICAL"}',
        ),
    ],
    "openai": [
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 2\n- Alerts after dedup    : 2\n- Cluster count         : 1\n\n### Cluster sec456 — C2 Communication\n- Priority    : MEDIUM\n- Score       : 50.0\n- Alert count : 2\n- Reason      : dest domain\n- IOCs        : evil.example.com\n- Techniques  : T1071.001 (Application Layer Protocol, Command and Control)\n- Sample alerts:\n  * [MEDIUM] DNS query to suspicious domain (dest_ip=evil.example.com)",
            output='{"executive_summary":"Processed 2 alerts (2 after deduplication), grouped into 1 cluster. Suspected C2 communication to external domain warrants investigation.","cluster_summaries":[{"cluster_id":"sec456","narrative":"2 MEDIUM alert(s) grouped by destination domain. Multiple DNS queries to evil.example.com detected. ATT&CK: T1071.001 (Application Layer Protocol).","recommendations":[{"action":"Block domain evil.example.com at DNS resolver","priority":"WITHIN_24H","rationale":"Prevent command and control communication while investigation proceeds."},{"action":"Review network logs for data exfiltration to evil.example.com","priority":"WITHIN_1H","rationale":"Confirm scope of potential C2 communication."}]}],"overall_priority":"MEDIUM"}',
        ),
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 2\n- Alerts after dedup    : 2\n- Cluster count         : 1\n\n### Cluster p1oai — Phishing Chain with New IOC Types\n- Priority    : CRITICAL\n- Score       : 152.0\n- Alert count : 2\n- Reason      : shared IOC overlap\n- IOCs        : CVE-2024-3400, T1566.001, HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater, ps_encoded:a1b2c3d4e5f6a7b8 (320b)\n- Techniques  : T1566.001 (Spearphishing Attachment, Initial Access); T1547.001 (Registry Run Keys, Persistence)",
            output='{"executive_summary":"Processed 2 alerts (2 after deduplication), grouped into 1 cluster. CRITICAL: active exploitation of CVE-2024-3400 with obfuscated PowerShell and registry persistence confirmed.","cluster_summaries":[{"cluster_id":"p1oai","narrative":"2 CRITICAL alert(s) with CVE-2024-3400 exploitation (T1566.001), PowerShell encoded execution (ps_encoded stub — deobfuscation required), and HKCU Run-key persistence (T1547.001). Attack chain is complete from initial access to persistence.","recommendations":[{"action":"Contain affected systems immediately — disconnect from network","priority":"IMMEDIATE","rationale":"Complete attack chain with persistence indicates active compromise."},{"action":"Remove registry persistence key HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater","priority":"IMMEDIATE","rationale":"Persistence mechanism active; removal blocks reinfection post-reimaging."},{"action":"Decode PowerShell payload in isolated sandbox","priority":"WITHIN_1H","rationale":"Obfuscated execution payload may contain secondary C2 or data-exfiltration logic."},{"action":"Patch CVE-2024-3400 on all internet-facing systems","priority":"WITHIN_1H","rationale":"Reduces attack surface for identical campaigns targeting unpatched hosts."}]}],"overall_priority":"CRITICAL"}',
        ),
    ],
    "ollama": [
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 1\n- Alerts after dedup    : 1\n- Cluster count         : 1\n\n### Cluster abc111 — Phishing\n- Priority    : LOW\n- Score       : 20.0\n- Alert count : 1\n- Reason      : subject line\n- IOCs        : none\n- Techniques  : none mapped",
            output='{"executive_summary":"Processed 1 alert (1 after deduplication), grouped into 1 cluster. Low-confidence phishing detection.","cluster_summaries":[{"cluster_id":"abc111","narrative":"1 LOW alert(s) grouped by subject line match. No IOCs or ATT&CK mapping.","recommendations":[{"action":"Monitor for escalation","priority":"MONITOR","rationale":"Low-confidence cluster; re-evaluate if additional alerts arrive."}]}],"overall_priority":"LOW"}',
        ),
        PromptExample(
            input="## Triage Report\n- Total alerts ingested : 2\n- Alerts after dedup    : 2\n- Cluster count         : 1\n\n### Cluster p1oll — Phishing Chain with New IOC Types\n- Priority    : CRITICAL\n- Score       : 140.0\n- Alert count : 2\n- Reason      : shared IOC overlap\n- IOCs        : CVE-2024-3400, T1566.001, HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater, ps_encoded:a1b2c3d4e5f6a7b8 (320b)\n- Techniques  : T1566.001 (Spearphishing, Initial Access); T1547.001 (Registry Run Keys, Persistence)",
            output='{"executive_summary":"2 alerts in 1 CRITICAL cluster. CVE exploitation, encoded PowerShell, registry persistence all active.","cluster_summaries":[{"cluster_id":"p1oll","narrative":"CVE-2024-3400 used for initial access. ps_encoded payload executed. HKCU Run key created for persistence. Full attack chain present.","recommendations":[{"action":"Isolate affected hosts","priority":"IMMEDIATE","rationale":"Active persistence and obfuscated execution confirm compromise."},{"action":"Remove Run key HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater","priority":"IMMEDIATE","rationale":"Clears persistence before reimaging."},{"action":"Patch CVE-2024-3400","priority":"WITHIN_1H","rationale":"Closes initial access vector."}]}],"overall_priority":"CRITICAL"}',
        ),
    ],
}


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _safe_ioc_for_prompt(ioc: str) -> str:
    """Replace ps_encoded raw base64 with a SHA-256 prefix + byte-length stub."""
    if not ioc.startswith("ps_encoded:"):
        return ioc
    payload = ioc[len("ps_encoded:"):]
    try:
        decoded = base64.b64decode(payload)
        digest = hashlib.sha256(decoded).hexdigest()[:16]  # SAFE-SLICE: 16-char prefix for stub label only; full hash not needed
        return f"ps_encoded:{digest} ({len(decoded)}b)"
    except Exception:
        return f"ps_encoded:[decode-error] ({len(payload)}b)"


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
            ioc_preview = [_safe_ioc_for_prompt(ioc) for ioc in cluster.iocs[:5]]  # SAFE-SLICE: IOC preview only; sanitised before LLM; remaining count shown in suffix
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

        # Alert type distribution: 1 representative sample per unique title, sorted by max severity.
        # This ensures the LLM sees the full statistical picture of the cluster rather than
        # an arbitrary first-N slice that may be dominated by low-signal noise.
        if cluster.alerts:
            # Build: title_key → (count, max_severity, representative_alert)
            seen: dict[str, list] = {}
            for alert in cluster.alerts:
                key = alert.title if "title" not in redact else "[title redacted]"
                if key not in seen:
                    seen[key] = [1, alert.severity, alert]
                else:
                    seen[key][0] += 1
                    if alert.severity.score > seen[key][1].score:
                        seen[key][1] = alert.severity

            sorted_types = sorted(
                seen.items(),
                key=lambda kv: kv[1][1].score,
                reverse=True,
            )

            _SHOW = 10
            n_types = len(sorted_types)
            n_total = len(cluster.alerts)
            lines.append(
                f"- Alert type breakdown ({n_types} distinct type(s), {n_total} total):"
            )
            for title_key, (count, max_sev, rep) in sorted_types[:_SHOW]:  # SAFE-SLICE: severity-sorted; highest-severity types shown first; overflow count shown below
                optional_fields: list[tuple[str, str | None]] = [
                    ("source_ip", rep.source_ip),
                    ("dest_ip", rep.dest_ip),
                    ("user", rep.user),
                    ("host", rep.host),
                ]
                detail_parts: list[str] = []
                for field_name, field_val in optional_fields:
                    if field_val is None:
                        continue
                    if field_name in redact:
                        detail_parts.append(f"{field_name}=[redacted]")
                    else:
                        detail_parts.append(f"{field_name}={field_val}")
                sample = f" — sample: ({', '.join(detail_parts)})" if detail_parts else ""
                lines.append(f"  [{max_sev.value}] {title_key}  ×{count}{sample}")
            if n_types > _SHOW:
                lines.append(f"  … ({n_types - _SHOW} more type(s))")

        lines.append("")  # blank line between clusters

    # ------------------------------------------------------------------ #
    # Closing instruction
    # ------------------------------------------------------------------ #
    lines.append(
        "Based on the report above, produce the triage summary JSON as specified "
        "in the system prompt. Do not include any text outside the JSON object."
    )

    return "\n".join(lines)
