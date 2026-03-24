"""STIX 2.1 bundle generation from sift TriageReport.

Generates valid STIX 2.1 JSON bundles without requiring the heavy ``stix2``
library. Each cluster becomes a ``grouping`` SDO, IOCs become ``indicator``
SDOs with appropriate patterns, and relationships tie them together.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sift.models import ClusterPriority, TriageReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NAMESPACE = uuid.UUID("b1e66b95-5e5f-4d2f-9a7e-c1d88f9a6e5e")  # sift namespace


def _deterministic_id(sdo_type: str, *parts: str) -> str:
    """Create a deterministic STIX ID from type + parts (UUID-5)."""
    seed = ":".join(parts)
    return f"{sdo_type}--{uuid.uuid5(_NAMESPACE, seed)}"


def _now_iso() -> str:
    """Return current time in ISO 8601 format with UTC timezone."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _pattern_from_ioc(ioc: str, ioc_type: str | None = None) -> str:
    """Map IOC to a STIX indicator pattern.

    Auto-detects IOC type if not provided:
    - IPv4 addresses
    - IPv6 addresses
    - Domain names
    - URLs
    - Email addresses
    - MD5/SHA1/SHA256 hashes
    """
    # Escape chars that have special meaning in STIX pattern syntax.
    # Order matters: backslash first, then others.
    safe = ioc.replace("\\", "\\\\").replace("'", "\\'").replace("]", "\\]")
    ioc_type_lower = (ioc_type or "").lower()

    # Explicit type mapping
    if ioc_type_lower == "sha256":
        return f"[file:hashes.'SHA-256' = '{safe}']"
    if ioc_type_lower == "sha1":
        return f"[file:hashes.'SHA-1' = '{safe}']"
    if ioc_type_lower == "md5":
        return f"[file:hashes.MD5 = '{safe}']"
    if ioc_type_lower == "ipv4":
        return f"[ipv4-addr:value = '{safe}']"
    if ioc_type_lower == "ipv6":
        return f"[ipv6-addr:value = '{safe}']"
    if ioc_type_lower == "domain":
        return f"[domain-name:value = '{safe}']"
    if ioc_type_lower == "url":
        return f"[url:value = '{safe}']"
    if ioc_type_lower == "email":
        return f"[email-addr:value = '{safe}']"

    # Auto-detect: check hash patterns
    ioc_lower = ioc.lower()
    if len(ioc) == 32 and all(c in "0123456789abcdef" for c in ioc_lower):
        return f"[file:hashes.MD5 = '{safe}']"
    if len(ioc) == 40 and all(c in "0123456789abcdef" for c in ioc_lower):
        return f"[file:hashes.'SHA-1' = '{safe}']"
    if len(ioc) == 64 and all(c in "0123456789abcdef" for c in ioc_lower):
        return f"[file:hashes.'SHA-256' = '{safe}']"

    # Auto-detect: check URL pattern
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return f"[url:value = '{safe}']"

    # Auto-detect: check email pattern
    if "@" in ioc and "." in ioc:
        return f"[email-addr:value = '{safe}']"

    # Auto-detect: check IPv4 pattern
    if ioc.count(".") == 3 and all(part.isdigit() for part in ioc.split(".")):
        return f"[ipv4-addr:value = '{safe}']"

    # Auto-detect: check IPv6 pattern
    if ":" in ioc:
        return f"[ipv6-addr:value = '{safe}']"

    # Default to domain or artifact
    if "." in ioc and not ioc.startswith("["):
        return f"[domain-name:value = '{safe}']"

    return f"[artifact:payload_bin = '{safe}']"


def _priority_to_severity(priority: ClusterPriority) -> str:
    """Map ClusterPriority to STIX severity level."""
    mapping = {
        ClusterPriority.NOISE: "low",
        ClusterPriority.LOW: "low",
        ClusterPriority.MEDIUM: "medium",
        ClusterPriority.HIGH: "high",
        ClusterPriority.CRITICAL: "high",
    }
    return mapping.get(priority, "medium")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class STIXExporter:
    """Convert a sift TriageReport to a STIX 2.1 JSON bundle."""

    def __init__(self, report: TriageReport) -> None:
        """Initialize the exporter with a TriageReport.

        Args:
            report: The sift TriageReport to export to STIX.
        """
        self.report = report
        self.now = _now_iso()
        self.objects: list[dict[str, Any]] = []

    def to_stix_bundle(self) -> dict[str, Any]:
        """Convert the report to a STIX 2.1 Bundle dict.

        Returns:
            A valid STIX 2.1 Bundle object as a dictionary.
        """
        self._create_objects()
        bundle = {
            "type": "bundle",
            "spec_version": "2.1",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": self.objects,
        }
        return bundle

    def to_stix_bundle_string(self) -> str:
        """Convert the report to a STIX 2.1 JSON bundle string.

        Returns:
            A valid STIX 2.1 JSON string.
        """
        bundle = self.to_stix_bundle()
        return json.dumps(bundle, indent=2, default=str)

    def _create_objects(self) -> None:
        """Populate self.objects with STIX SDOs from the report."""
        # Track IDs to avoid duplicates
        seen_ids: set[str] = set()

        for cluster in self.report.clusters:
            # 1. Grouping SDO (one per cluster)
            grouping = self._create_grouping(cluster)
            if grouping["id"] not in seen_ids:
                self.objects.append(grouping)
                seen_ids.add(grouping["id"])
            grouping_id = grouping["id"]

            # 2. Indicator SDOs (one per IOC in cluster)
            for ioc in cluster.iocs:
                indicator = self._create_indicator(ioc, grouping_id)
                if indicator["id"] not in seen_ids:
                    self.objects.append(indicator)
                    seen_ids.add(indicator["id"])

            # 3. Note SDO for cluster summary
            if cluster.label:
                note = self._create_note(cluster, grouping_id)
                if note["id"] not in seen_ids:
                    self.objects.append(note)
                    seen_ids.add(note["id"])

            # 4. Additional note for AI narrative (if summary exists)
            if self.report.summary:
                for cs in self.report.summary.cluster_summaries:
                    if cs.cluster_id == cluster.id and cs.narrative:
                        narrative_note = self._create_narrative_note(cluster, cs.narrative, grouping_id)
                        if narrative_note["id"] not in seen_ids:
                            self.objects.append(narrative_note)
                            seen_ids.add(narrative_note["id"])

            # 5. Relationship: Grouping aggregates Indicators
            for ioc in cluster.iocs:
                indicator_id = _deterministic_id("indicator", grouping_id, ioc)
                rel = self._create_relationship(grouping_id, "aggregates", indicator_id)
                if rel["id"] not in seen_ids:
                    self.objects.append(rel)
                    seen_ids.add(rel["id"])

    def _create_grouping(self, cluster) -> dict[str, Any]:
        """Create a Grouping SDO for a cluster."""
        grouping_id = _deterministic_id("grouping", cluster.id)
        severity = _priority_to_severity(cluster.priority)

        return {
            "type": "grouping",
            "spec_version": "2.1",
            "id": grouping_id,
            "created": self.now,
            "modified": self.now,
            "name": cluster.label,
            "description": f"Alert cluster: {cluster.label}. Priority: {cluster.priority.value}",
            "context": cluster.priority.value.lower(),
            "object_refs": [_deterministic_id("indicator", grouping_id, ioc) for ioc in cluster.iocs],
        }

    def _create_indicator(self, ioc: str, grouping_id: str) -> dict[str, Any]:
        """Create an Indicator SDO for an IOC.

        Args:
            ioc: The IOC string (IP, domain, URL, hash, etc.).
            grouping_id: The ID of the parent Grouping SDO.

        Returns:
            A valid STIX 2.1 Indicator SDO.
        """
        indicator_id = _deterministic_id("indicator", grouping_id, ioc)

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": self.now,
            "modified": self.now,
            "name": f"IOC: {ioc}",
            "description": f"Indicator detected in cluster alerts",
            "pattern": _pattern_from_ioc(ioc),
            "pattern_type": "stix",
            "valid_from": self.now,
            "labels": ["malicious-activity"],
        }

    def _create_note(self, cluster, grouping_id: str) -> dict[str, Any]:
        """Create a Note SDO for cluster summary.

        Args:
            cluster: The Cluster object.
            grouping_id: The ID of the parent Grouping SDO.

        Returns:
            A valid STIX 2.1 Note SDO.
        """
        note_id = _deterministic_id("note", grouping_id, "summary")

        content = f"Cluster: {cluster.label}\n"
        content += f"Priority: {cluster.priority.value}\n"
        content += f"Alerts: {len(cluster.alerts)}\n"
        content += f"IOCs: {len(cluster.iocs)}\n"
        content += f"Confidence: {cluster.confidence:.1%}\n"
        if cluster.cluster_reason:
            content += f"Reason: {cluster.cluster_reason}\n"

        return {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": self.now,
            "modified": self.now,
            "abstract": "Cluster Summary",
            "content": content.strip(),
            "object_refs": [grouping_id],
        }

    def _create_narrative_note(self, cluster, narrative: str, grouping_id: str) -> dict[str, Any]:
        """Create a Note SDO for AI-generated narrative.

        Args:
            cluster: The Cluster object.
            narrative: The AI narrative text.
            grouping_id: The ID of the parent Grouping SDO.

        Returns:
            A valid STIX 2.1 Note SDO.
        """
        note_id = _deterministic_id("note", grouping_id, "narrative")

        return {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": self.now,
            "modified": self.now,
            "abstract": "AI Analysis Narrative",
            "content": narrative,
            "object_refs": [grouping_id],
        }

    def _create_relationship(self, source_id: str, relationship_type: str, target_id: str) -> dict[str, Any]:
        """Create a Relationship SDO.

        Args:
            source_id: The source object ID.
            relationship_type: The STIX relationship type (e.g., "aggregates", "indicates").
            target_id: The target object ID.

        Returns:
            A valid STIX 2.1 Relationship SDO.
        """
        rel_id = _deterministic_id("relationship", source_id, relationship_type, target_id)

        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": self.now,
            "modified": self.now,
            "relationship_type": relationship_type,
            "source_ref": source_id,
            "target_ref": target_id,
        }


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def to_stix_bundle(report: TriageReport) -> dict[str, Any]:
    """Convert a TriageReport to a STIX 2.1 Bundle dictionary.

    Args:
        report: The sift TriageReport to export.

    Returns:
        A valid STIX 2.1 Bundle object as a dictionary.
    """
    exporter = STIXExporter(report)
    return exporter.to_stix_bundle()


def to_stix_bundle_string(report: TriageReport) -> str:
    """Convert a TriageReport to a STIX 2.1 JSON bundle string.

    Args:
        report: The sift TriageReport to export.

    Returns:
        A valid STIX 2.1 JSON string.
    """
    exporter = STIXExporter(report)
    return exporter.to_stix_bundle_string()
