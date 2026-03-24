"""MITRE ATT&CK technique ID validation utilities."""

from __future__ import annotations

import logging
import re

TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
logger = logging.getLogger(__name__)


def is_valid_technique_id(technique_id: str) -> bool:
    """Return True if technique_id matches T1234 or T1234.001 format."""
    return bool(TECHNIQUE_PATTERN.match(technique_id))


def validate_technique_ids(ids: list[str]) -> list[str]:
    """Filter list to only valid technique IDs; log WARNING for each invalid one."""
    valid = []
    for tid in ids:
        if is_valid_technique_id(tid):
            valid.append(tid)
        else:
            logger.warning("Invalid ATT&CK technique ID ignored: %r", tid)
    return valid


def normalize_technique_id(technique_id: str) -> str:
    """Uppercase and strip surrounding whitespace."""
    return technique_id.strip().upper()
