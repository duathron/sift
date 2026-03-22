"""Tests for sift.pipeline.dedup — fingerprint-based alert deduplication."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from sift.pipeline.dedup import deduplicate, DeduplicatorConfig, DedupStats
from sift.models import Alert, AlertSeverity


# ---------------------------------------------------------------------------
# Alert factory
# ---------------------------------------------------------------------------


def make_alert(
    id: str = "a1",
    title: str = "Test Alert",
    source_ip: str = "1.2.3.4",
    dest_ip: str | None = None,
    category: str | None = None,
    timestamp: datetime | None = None,
) -> Alert:
    return Alert(
        id=id,
        title=title,
        source_ip=source_ip,
        dest_ip=dest_ip,
        category=category,
        timestamp=timestamp,
    )


# Convenience timestamp helpers
def ts(offset_minutes: int = 0) -> datetime:
    """Return a UTC datetime offset from a fixed epoch by *offset_minutes*."""
    base = datetime(2026, 3, 22, 10, 0, 0, tzinfo=timezone.utc)
    return base + timedelta(minutes=offset_minutes)


# ---------------------------------------------------------------------------
# 1. Empty input
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_list_and_zero_stats() -> None:
    alerts, stats = deduplicate([])

    assert alerts == []
    assert stats.original_count == 0
    assert stats.deduplicated_count == 0
    assert stats.removed_count == 0


# ---------------------------------------------------------------------------
# 2. Single alert — nothing to deduplicate
# ---------------------------------------------------------------------------


def test_single_alert_is_kept_with_no_removal() -> None:
    alert = make_alert()
    alerts, stats = deduplicate([alert])

    assert len(alerts) == 1
    assert alerts[0] is alert
    assert stats.removed_count == 0


# ---------------------------------------------------------------------------
# 3. Two identical alerts with no timestamp — pure fingerprint dedup
# ---------------------------------------------------------------------------


def test_two_identical_no_timestamp_keeps_one() -> None:
    a1 = make_alert(id="a1")
    a2 = make_alert(id="a2")  # same fingerprint, no timestamp

    alerts, stats = deduplicate([a1, a2])

    assert len(alerts) == 1
    assert stats.removed_count == 1
    assert stats.original_count == 2
    assert stats.deduplicated_count == 1


# ---------------------------------------------------------------------------
# 4. Two identical alerts within the default 5-minute time window → 1 kept
# ---------------------------------------------------------------------------


def test_two_identical_within_time_window_keeps_one() -> None:
    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=ts(3))  # 3 minutes later — inside 5-min window

    alerts, stats = deduplicate([a1, a2])

    assert len(alerts) == 1
    assert stats.removed_count == 1


# ---------------------------------------------------------------------------
# 5. Two identical alerts outside the 5-minute window → both kept
# ---------------------------------------------------------------------------


def test_two_identical_outside_time_window_keeps_both() -> None:
    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=ts(10))  # 10 minutes later — outside default window

    alerts, stats = deduplicate([a1, a2])

    assert len(alerts) == 2
    assert stats.removed_count == 0


# ---------------------------------------------------------------------------
# 6. Two alerts with different titles → both kept
# ---------------------------------------------------------------------------


def test_different_titles_keeps_both() -> None:
    a1 = make_alert(id="a1", title="Malware Detected", timestamp=ts(0))
    a2 = make_alert(id="a2", title="Phishing Attempt", timestamp=ts(1))

    alerts, stats = deduplicate([a1, a2])

    assert len(alerts) == 2
    assert stats.removed_count == 0


# ---------------------------------------------------------------------------
# 7. Same title, different source_ip → different fingerprint → both kept
# ---------------------------------------------------------------------------


def test_same_title_different_source_ip_keeps_both() -> None:
    a1 = make_alert(id="a1", source_ip="1.2.3.4", timestamp=ts(0))
    a2 = make_alert(id="a2", source_ip="5.6.7.8", timestamp=ts(1))

    alerts, stats = deduplicate([a1, a2])

    assert len(alerts) == 2
    assert stats.removed_count == 0


# ---------------------------------------------------------------------------
# 8. time_window_minutes=0 → fingerprint-only dedup, no windowing
# ---------------------------------------------------------------------------


def test_time_window_zero_drops_repeated_fingerprint_regardless_of_gap() -> None:
    config = DeduplicatorConfig(time_window_minutes=0)

    # 60 minutes apart — would survive a 5-min window, but not when window=0
    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=ts(60))

    alerts, stats = deduplicate([a1, a2], config=config)

    assert len(alerts) == 1
    assert stats.removed_count == 1


# ---------------------------------------------------------------------------
# 9. DedupStats.removed_pct — correct percentage
# ---------------------------------------------------------------------------


def test_removed_pct_correct_calculation() -> None:
    # 2 out of 4 removed → 50.0 %
    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=ts(1))   # dup of a1
    a3 = make_alert(id="a3", title="Other Alert", source_ip="9.9.9.9", timestamp=ts(0))
    a4 = make_alert(id="a4", title="Other Alert", source_ip="9.9.9.9", timestamp=ts(2))  # dup of a3

    _, stats = deduplicate([a1, a2, a3, a4])

    assert stats.removed_count == 2
    assert stats.original_count == 4
    assert stats.removed_pct == 50.0


# ---------------------------------------------------------------------------
# 10. DedupStats.removed_pct with 0 alerts — no ZeroDivisionError
# ---------------------------------------------------------------------------


def test_removed_pct_zero_alerts_no_division_error() -> None:
    _, stats = deduplicate([])

    # Must not raise; must return 0.0
    assert stats.removed_pct == 0.0


# ---------------------------------------------------------------------------
# 11. Mixed batch: 5 alerts, 2 pairs of dups + 1 unique → 3 retained
# ---------------------------------------------------------------------------


def test_mixed_batch_two_pairs_one_unique() -> None:
    # Pair 1: same fingerprint, within window
    a1 = make_alert(id="a1", title="Brute Force", source_ip="10.0.0.1", timestamp=ts(0))
    a2 = make_alert(id="a2", title="Brute Force", source_ip="10.0.0.1", timestamp=ts(2))

    # Pair 2: same fingerprint, within window
    a3 = make_alert(id="a3", title="Port Scan", source_ip="10.0.0.2", timestamp=ts(0))
    a4 = make_alert(id="a4", title="Port Scan", source_ip="10.0.0.2", timestamp=ts(4))

    # Unique
    a5 = make_alert(id="a5", title="Ransomware", source_ip="10.0.0.3", timestamp=ts(0))

    alerts, stats = deduplicate([a1, a2, a3, a4, a5])

    assert len(alerts) == 3
    assert stats.original_count == 5
    assert stats.removed_count == 2
    assert stats.deduplicated_count == 3


# ---------------------------------------------------------------------------
# 12. Alerts with None timestamp vs alerts with timestamp → fingerprint-only dedup
# ---------------------------------------------------------------------------


def test_none_timestamp_deduped_against_timestamped_fingerprint() -> None:
    # a1 is timestamped; a2 has the same fingerprint but no timestamp.
    # Per the implementation, a2 should be dropped because a1 is already in seen_ts.
    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=None)  # same fingerprint, no timestamp

    alerts, stats = deduplicate([a1, a2])

    assert len(alerts) == 1
    assert stats.removed_count == 1


def test_none_timestamp_pure_fingerprint_dedup_among_themselves() -> None:
    # Both have no timestamp; second should be dropped on fingerprint alone.
    a1 = make_alert(id="a1", timestamp=None)
    a2 = make_alert(id="a2", timestamp=None)

    alerts, stats = deduplicate([a1, a2])

    assert len(alerts) == 1
    assert stats.removed_count == 1


# ---------------------------------------------------------------------------
# 13. Large time_window effectively acts as "keep distinct fingerprints only"
# ---------------------------------------------------------------------------


def test_very_large_window_behaves_like_pure_fingerprint_dedup() -> None:
    """A huge window covers any plausible gap, so only unique fingerprints survive."""
    config = DeduplicatorConfig(time_window_minutes=99_999)

    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=ts(500))   # far apart but same fingerprint
    a3 = make_alert(id="a3", title="Different", source_ip="2.2.2.2", timestamp=ts(0))

    alerts, stats = deduplicate([a1, a2, a3], config=config)

    assert len(alerts) == 2
    assert stats.removed_count == 1


# ---------------------------------------------------------------------------
# 14. First occurrence is preserved when two duplicates exist
# ---------------------------------------------------------------------------


def test_first_occurrence_by_list_order_is_kept() -> None:
    first = make_alert(id="first", timestamp=ts(0))
    second = make_alert(id="second", timestamp=ts(1))  # dup of first, within window

    alerts, stats = deduplicate([first, second])

    assert len(alerts) == 1
    assert alerts[0].id == "first"


# ---------------------------------------------------------------------------
# 15. DedupStats fields sum correctly
# ---------------------------------------------------------------------------


def test_dedupstats_counts_sum_correctly() -> None:
    # 3 unique, 2 removed from 5 total
    a1 = make_alert(id="a1", title="A", timestamp=ts(0))
    a2 = make_alert(id="a2", title="A", timestamp=ts(1))   # dup
    a3 = make_alert(id="a3", title="B", source_ip="2.2.2.2", timestamp=ts(0))
    a4 = make_alert(id="a4", title="B", source_ip="2.2.2.2", timestamp=ts(2))   # dup
    a5 = make_alert(id="a5", title="C", source_ip="3.3.3.3", timestamp=ts(0))

    _, stats = deduplicate([a1, a2, a3, a4, a5])

    assert stats.original_count == stats.deduplicated_count + stats.removed_count
    assert stats.original_count == 5
    assert stats.deduplicated_count == 3
    assert stats.removed_count == 2


# ---------------------------------------------------------------------------
# Bonus: custom time window smaller than default
# ---------------------------------------------------------------------------


def test_custom_narrow_window_drops_alert_within_window() -> None:
    config = DeduplicatorConfig(time_window_minutes=2)

    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=ts(1))  # 1 min — inside 2-min window → dup

    alerts, stats = deduplicate([a1, a2], config=config)

    assert len(alerts) == 1
    assert stats.removed_count == 1


def test_custom_narrow_window_keeps_alert_outside_window() -> None:
    config = DeduplicatorConfig(time_window_minutes=2)

    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=ts(3))  # 3 min — outside 2-min window → kept

    alerts, stats = deduplicate([a1, a2], config=config)

    assert len(alerts) == 2
    assert stats.removed_count == 0


# ---------------------------------------------------------------------------
# Bonus: default config is applied when none is passed
# ---------------------------------------------------------------------------


def test_default_config_applied_when_none_passed() -> None:
    """Passing config=None should use a 5-minute window (the default)."""
    a1 = make_alert(id="a1", timestamp=ts(0))
    a2 = make_alert(id="a2", timestamp=ts(4))   # 4 min — inside default 5-min window

    alerts, stats = deduplicate([a1, a2], config=None)

    assert len(alerts) == 1
    assert stats.removed_count == 1


# ---------------------------------------------------------------------------
# Bonus: case and whitespace normalization in title
# ---------------------------------------------------------------------------


def test_title_case_and_whitespace_normalization_produces_same_fingerprint() -> None:
    """Titles differing only in case or extra whitespace share the same fingerprint."""
    a1 = make_alert(id="a1", title="Brute  Force Login", timestamp=ts(0))
    a2 = make_alert(id="a2", title="BRUTE FORCE LOGIN", timestamp=ts(1))

    alerts, stats = deduplicate([a1, a2])

    assert len(alerts) == 1
    assert stats.removed_count == 1
