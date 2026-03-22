"""Alert deduplication — fingerprint-based with optional time-windowing.

Strategy
--------
A fingerprint is computed for each alert by hashing the four-tuple:

    (title_normalized, source_ip, dest_ip, category)

All components are lowercased; ``None`` fields are treated as empty strings
before hashing.  Within a configurable time window (default 5 minutes), only
the *first* occurrence of a fingerprint is kept; subsequent duplicates are
discarded.  Alerts that carry no timestamp bypass time-windowing and are
deduplicated purely on fingerprint across the entire input set.
"""

from __future__ import annotations

import hashlib
import re
from datetime import timedelta
from typing import Optional

from pydantic import BaseModel, computed_field

from sift.models import Alert


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class DeduplicatorConfig(BaseModel):
    """Configuration for the deduplication stage.

    Attributes
    ----------
    time_window_minutes:
        Alerts with the same fingerprint that arrive within this many minutes
        of the first seen occurrence are considered duplicates.  Set to ``0``
        to disable time-windowing and deduplicate on fingerprint alone
        (across all timestamps).
    """

    time_window_minutes: int = 5


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class DedupStats(BaseModel):
    """Statistics produced by a single :func:`deduplicate` call.

    Attributes
    ----------
    original_count:
        Number of alerts supplied to :func:`deduplicate`.
    deduplicated_count:
        Number of alerts retained after deduplication.
    removed_count:
        Number of duplicate alerts discarded.
    """

    original_count: int
    deduplicated_count: int
    removed_count: int

    @computed_field  # type: ignore[misc]
    @property
    def removed_pct(self) -> float:
        """Percentage of alerts removed as duplicates (0.0–100.0).

        Returns ``0.0`` when ``original_count`` is zero to avoid division by
        zero.
        """
        if self.original_count == 0:
            return 0.0
        return round(self.removed_count / self.original_count * 100, 2)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_title(title: str) -> str:
    """Lowercase and collapse internal whitespace in *title*.

    This prevents trivial variations (extra spaces, mixed case) from
    producing different fingerprints for semantically identical alerts.
    """
    return _WHITESPACE_RE.sub(" ", title.strip().lower())


def _fingerprint(alert: Alert) -> str:
    """Return a stable SHA-256 hex fingerprint for *alert*.

    The fingerprint is derived from the four-tuple
    ``(title_normalized, source_ip, dest_ip, category)``.  Missing fields
    contribute an empty string so that the fingerprint space remains
    well-defined regardless of how sparse an alert is.
    """
    parts = (
        _normalize_title(alert.title),
        (alert.source_ip or "").lower(),
        (alert.dest_ip or "").lower(),
        (alert.category or "").lower(),
    )
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def deduplicate(
    alerts: list[Alert],
    config: Optional[DeduplicatorConfig] = None,
) -> tuple[list[Alert], DedupStats]:
    """Remove duplicate alerts from *alerts*, preserving insertion order.

    Each alert is assigned a fingerprint (see :func:`_fingerprint`).  The
    deduplication pass keeps the *first* occurrence of each fingerprint and
    discards all later ones that fall within the configured time window.

    Alerts without a ``timestamp`` are handled in a separate pass that
    considers them duplicates if their fingerprint has already been seen at
    any point in the timestamped set *or* among other timestamp-less alerts.

    Parameters
    ----------
    alerts:
        Input list of normalized :class:`~sift.models.Alert` objects.
        The list is not modified in place.
    config:
        Optional :class:`DeduplicatorConfig`.  When *None*, defaults are used
        (``time_window_minutes=5``).

    Returns
    -------
    tuple[list[Alert], DedupStats]
        A two-tuple of ``(retained_alerts, stats)``.  ``retained_alerts``
        preserves the relative order of the input.
    """
    if config is None:
        config = DeduplicatorConfig()

    window = timedelta(minutes=config.time_window_minutes)
    use_window = config.time_window_minutes > 0

    # Map fingerprint → list of timestamps already seen (for windowed dedup).
    # Only timestamps of *retained* alerts are stored here.
    seen_ts: dict[str, list] = {}  # fingerprint → list[datetime]

    # For no-timestamp alerts: set of fingerprints already retained.
    seen_no_ts: set[str] = set()

    retained: list[Alert] = []

    for alert in alerts:
        fp = _fingerprint(alert)

        if alert.timestamp is None:
            # ----------------------------------------------------------------
            # No-timestamp path: pure fingerprint dedup across all inputs.
            # Also treated as duplicate if the fingerprint appeared in the
            # timestamped set (same entity, just missing a timestamp).
            # ----------------------------------------------------------------
            already_seen_in_ts = fp in seen_ts
            if already_seen_in_ts or fp in seen_no_ts:
                continue
            seen_no_ts.add(fp)
            retained.append(alert)
        else:
            # ----------------------------------------------------------------
            # Timestamped path: fingerprint + time-window dedup.
            # ----------------------------------------------------------------
            ts = alert.timestamp
            if fp in seen_ts and use_window:
                # Check whether this alert falls within the window of any
                # previously retained alert with the same fingerprint.
                if any(abs((ts - prev).total_seconds()) <= window.total_seconds()
                       for prev in seen_ts[fp]):
                    continue
                # Outside all windows — treat as a new distinct occurrence.
                seen_ts[fp].append(ts)
            elif fp in seen_ts and not use_window:
                # Time-windowing disabled: any repeated fingerprint is a dup.
                continue
            else:
                seen_ts[fp] = [ts]

            retained.append(alert)

    removed = len(alerts) - len(retained)
    stats = DedupStats(
        original_count=len(alerts),
        deduplicated_count=len(retained),
        removed_count=removed,
    )
    return retained, stats
