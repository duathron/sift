"""
Export utilities for sift TriageReport.

Supports JSON (full fidelity) and CSV (flat per-alert and per-cluster views).
All functions return the serialized string and optionally write to a file.

By default ``ps_encoded:<base64>`` IOCs are replaced with a SHA-256 stub
before export so the raw obfuscated payload never leaks into analyst
tooling, ticket systems, or downstream LLM contexts. Pass
``include_raw_payload=True`` (CLI: ``--include-raw-payload``) for the
forensic-record path that preserves the original base-64.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from copy import deepcopy
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sift.models import TriageReport

from sift.pipeline.ioc_extractor import detect_ioc_type


def _ps_encoded_stub(ioc: str) -> str:
    """Return a SHA-256 stub label for a ``ps_encoded:<b64>`` IOC.

    Format: ``ps_encoded:<sha256_first_16hex> (<bytelen>B)``. Mirrors the
    formatter and STIX exporter sanitisation so all output channels render
    the same opaque-but-traceable identifier.
    """
    payload = ioc[len("ps_encoded:") :]
    try:
        raw = base64.b64decode(payload + "==", validate=False)
        digest = hashlib.sha256(raw).hexdigest()[:16]
        size = f"{len(raw)}B"
    except Exception:
        digest = "invalid"
        size = "?B"
    return f"ps_encoded:{digest} ({size})"


def _sanitize_ioc(ioc: str, include_raw_payload: bool = False) -> str:
    """Sanitise a single IOC for CSV export.

    Default behaviour replaces ``ps_encoded:<b64>`` with the literal
    ``ps_encoded:[REDACTED]`` sentinel for fixed-width column safety.
    When *include_raw_payload* is True the original IOC is returned
    unchanged (forensic record).
    """
    if include_raw_payload:
        return ioc
    if ioc.startswith("ps_encoded:"):
        return "ps_encoded:[REDACTED]"
    return ioc


def _sanitize_report(report: "TriageReport") -> "TriageReport":
    """Return a deep-copied report with ``ps_encoded:`` IOCs SHA-256-stubbed.

    Used by :func:`export_json` and the ticketing mapper to guarantee no
    raw obfuscated payload leaks into JSON output, ticket fields, or
    anything downstream that may forward content to LLM-adjacent systems.
    The original *report* is not mutated.
    """
    sanitized = deepcopy(report)

    def _scrub(iocs: list[str]) -> list[str]:
        return [
            _ps_encoded_stub(i) if i.startswith("ps_encoded:") else i
            for i in iocs
        ]

    for cluster in sanitized.clusters:
        cluster.iocs = _scrub(cluster.iocs)
        for alert in cluster.alerts:
            alert.iocs = _scrub(alert.iocs)

    return sanitized


def _ioc_types(iocs: list[str]) -> str:
    """Return distinct IOC type labels pipe-separated, preserving insertion order."""
    seen: dict[str, None] = {}
    for ioc in iocs:
        seen[detect_ioc_type(ioc)] = None
    return "|".join(seen.keys()) if seen else ""


def export_json(
    report: "TriageReport",
    path: Path | None = None,
    *,
    include_raw_payload: bool = False,
) -> str:
    """Serialize a TriageReport to a JSON string.

    Uses Pydantic's ``model_dump(mode="json")`` to ensure all fields are
    JSON-serializable (datetimes rendered as ISO-8601 strings, enums as
    their values, etc.).

    By default ``ps_encoded:<b64>`` IOCs are replaced with their SHA-256
    stub before serialisation so the raw obfuscated payload is never
    written to disk or stdout. Pass ``include_raw_payload=True`` for the
    forensic-record path.

    Args:
        report: The triage report to serialize.
        path:   Optional file path to write the JSON to.  Parent directories
                are created automatically.  If ``None`` the output is only
                returned, not written.
        include_raw_payload:
                When True, the report is serialised verbatim — ``ps_encoded``
                IOCs keep their full base-64 payload. Default False.

    Returns:
        The full JSON string.
    """
    target = report if include_raw_payload else _sanitize_report(report)
    payload: str = json.dumps(target.model_dump(mode="json"), indent=2)

    if path is not None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")

    return payload


def export_csv(
    report: "TriageReport",
    path: Path | None = None,
    *,
    include_raw_payload: bool = False,
) -> str:
    """Export a flat CSV with one row per alert.

    Each alert row is annotated with the metadata of the cluster it belongs
    to so that the output is self-contained for spreadsheet analysis.

    Columns
    -------
    alert_id, alert_timestamp, alert_severity, alert_title, alert_category,
    alert_source_ip, alert_dest_ip, alert_user, alert_host,
    alert_iocs (pipe-separated),
    cluster_id, cluster_label, cluster_priority, cluster_score

    Args:
        report: The triage report to export.
        path:   Optional file path to write the CSV to.  Parent directories
                are created automatically.  If ``None`` the output is only
                returned, not written.
        include_raw_payload:
                When True, ``ps_encoded`` IOCs keep their full base-64
                payload in the ``alert_iocs`` column. Default False —
                payload is replaced with ``ps_encoded:[REDACTED]``.

    Returns:
        The CSV string (including header row).
    """
    fieldnames = [
        "alert_id",
        "alert_timestamp",
        "alert_severity",
        "alert_title",
        "alert_category",
        "alert_source_ip",
        "alert_dest_ip",
        "alert_user",
        "alert_host",
        "alert_iocs",
        "alert_ioc_types",
        "cluster_id",
        "cluster_label",
        "cluster_priority",
        "cluster_score",
    ]

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=fieldnames,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()

    for cluster in report.clusters:
        cluster_priority_val = (
            cluster.priority.value
            if hasattr(cluster.priority, "value")
            else str(cluster.priority)
        )

        for alert in cluster.alerts:
            alert_severity_val = (
                alert.severity.value
                if hasattr(alert.severity, "value")
                else str(alert.severity)
            )
            timestamp_str = (
                alert.timestamp.isoformat()
                if hasattr(alert.timestamp, "isoformat")
                else str(alert.timestamp)
            )

            writer.writerow(
                {
                    "alert_id": alert.id,
                    "alert_timestamp": timestamp_str,
                    "alert_severity": alert_severity_val,
                    "alert_title": alert.title,
                    "alert_category": alert.category or "",
                    "alert_source_ip": alert.source_ip or "",
                    "alert_dest_ip": alert.dest_ip or "",
                    "alert_user": alert.user or "",
                    "alert_host": alert.host or "",
                    "alert_iocs": "|".join(_sanitize_ioc(i, include_raw_payload) for i in alert.iocs) if alert.iocs else "",
                    "alert_ioc_types": _ioc_types(alert.iocs) if alert.iocs else "",
                    "cluster_id": cluster.id,
                    "cluster_label": cluster.label,
                    "cluster_priority": cluster_priority_val,
                    "cluster_score": cluster.score,
                }
            )

    payload = buf.getvalue()

    if path is not None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")

    return payload


def export_cluster_csv(report: "TriageReport", path: Path | None = None) -> str:
    """Export a summary CSV with one row per cluster.

    Provides a high-level view of each cluster without expanding individual
    alert rows — useful for management dashboards or quick prioritisation.

    Columns
    -------
    cluster_id, label, priority, score, confidence, alert_count, ioc_count,
    technique_ids (pipe-separated), first_seen, last_seen, cluster_reason

    Args:
        report: The triage report to export.
        path:   Optional file path to write the CSV to.  Parent directories
                are created automatically.  If ``None`` the output is only
                returned, not written.

    Returns:
        The CSV string (including header row).
    """
    fieldnames = [
        "cluster_id",
        "label",
        "priority",
        "score",
        "confidence",
        "alert_count",
        "ioc_count",
        "technique_ids",
        "first_seen",
        "last_seen",
        "cluster_reason",
    ]

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=fieldnames,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()

    for cluster in report.clusters:
        priority_val = (
            cluster.priority.value
            if hasattr(cluster.priority, "value")
            else str(cluster.priority)
        )
        first_seen_str = (
            cluster.first_seen.isoformat()
            if hasattr(cluster.first_seen, "isoformat")
            else str(cluster.first_seen)
        )
        last_seen_str = (
            cluster.last_seen.isoformat()
            if hasattr(cluster.last_seen, "isoformat")
            else str(cluster.last_seen)
        )

        technique_ids: list[str] = []
        if cluster.techniques:
            for ref in cluster.techniques:
                # TechniqueRef may expose .id or be a plain string
                tid = getattr(ref, "id", None) or str(ref)
                technique_ids.append(tid)

        writer.writerow(
            {
                "cluster_id": cluster.id,
                "label": cluster.label,
                "priority": priority_val,
                "score": cluster.score,
                "confidence": cluster.confidence,
                "alert_count": len(cluster.alerts),
                "ioc_count": len(cluster.iocs) if cluster.iocs else 0,
                "technique_ids": "|".join(technique_ids),
                "first_seen": first_seen_str,
                "last_seen": last_seen_str,
                "cluster_reason": cluster.cluster_reason or "",
            }
        )

    payload = buf.getvalue()

    if path is not None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")

    return payload
