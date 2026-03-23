"""Tests for sift.cache — alert result caching layer.

Test plan
---------
TestCacheBasicOperations  (5 tests)
TestCacheEviction         (4 tests)
TestCacheStats            (4 tests)
TestCachePersistence      (4 tests)
TestCacheConfig           (3 tests)
"""

from __future__ import annotations

import json
import os
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sift.cache import AlertCache, CacheConfig, CacheEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(tmp_path: Path, **kwargs) -> CacheConfig:
    """Return a CacheConfig pointing at a temp directory.

    ``enabled=True`` by default for convenience; override via kwargs.
    """
    return CacheConfig(
        enabled=kwargs.pop("enabled", True),
        cache_dir=tmp_path / "cache",
        **kwargs,
    )


def sample_result(tag: str = "r1") -> dict:
    return {"tag": tag, "clusters": [], "priority": "HIGH"}


FP_A = "a" * 64  # 64-char hex-like fingerprint
FP_B = "b" * 64
FP_C = "c" * 64


# ---------------------------------------------------------------------------
# TestCacheBasicOperations
# ---------------------------------------------------------------------------


class TestCacheBasicOperations:
    """Five tests covering the fundamental get / put / invalidate / clear API."""

    def test_get_on_empty_cache_returns_none(self, tmp_path: Path) -> None:
        """get() on an empty cache must return None without raising."""
        cache = AlertCache(make_config(tmp_path))
        assert cache.get(FP_A) is None

    def test_put_and_get_roundtrip(self, tmp_path: Path) -> None:
        """A value stored with put() is retrievable with get()."""
        cache = AlertCache(make_config(tmp_path))
        result = sample_result("hello")
        cache.put(FP_A, result)
        assert cache.get(FP_A) == result

    def test_get_after_ttl_expiry_returns_none(self, tmp_path: Path) -> None:
        """get() returns None when the entry has exceeded its TTL."""
        cache = AlertCache(make_config(tmp_path, ttl_seconds=1))
        cache.put(FP_A, sample_result())

        # Manually backdate the entry so it appears expired.
        conn = cache._get_conn()
        past = (datetime.now(tz=timezone.utc) - timedelta(seconds=2)).isoformat()
        conn.execute(
            "UPDATE cache_entries SET created_at = ? WHERE fingerprint = ?",
            (past, FP_A),
        )
        conn.commit()

        assert cache.get(FP_A) is None

    def test_invalidate_removes_entry(self, tmp_path: Path) -> None:
        """invalidate() makes a previously stored entry unreachable."""
        cache = AlertCache(make_config(tmp_path))
        cache.put(FP_A, sample_result())
        cache.invalidate(FP_A)
        assert cache.get(FP_A) is None

    def test_clear_removes_all_entries(self, tmp_path: Path) -> None:
        """clear() removes every entry so all subsequent get() calls miss."""
        cache = AlertCache(make_config(tmp_path))
        for fp in (FP_A, FP_B, FP_C):
            cache.put(fp, sample_result(fp))

        cache.clear()

        for fp in (FP_A, FP_B, FP_C):
            assert cache.get(fp) is None


# ---------------------------------------------------------------------------
# TestCacheEviction
# ---------------------------------------------------------------------------


class TestCacheEviction:
    """Four tests covering LRU eviction behaviour."""

    def test_lru_eviction_when_max_entries_exceeded(self, tmp_path: Path) -> None:
        """Inserting beyond max_entries evicts exactly one entry."""
        cache = AlertCache(make_config(tmp_path, max_entries=2))
        cache.put(FP_A, sample_result("a"))
        cache.put(FP_B, sample_result("b"))
        # Third insert should trigger eviction of the LRU entry (FP_A).
        cache.put(FP_C, sample_result("c"))

        remaining = cache.stats()["entries"]
        assert remaining == 2

    def test_eviction_preserves_most_recently_accessed(self, tmp_path: Path) -> None:
        """After eviction the two most-recently-accessed entries survive."""
        cache = AlertCache(make_config(tmp_path, max_entries=2))
        cache.put(FP_A, sample_result("a"))
        cache.put(FP_B, sample_result("b"))
        # Access FP_A to make it more recent than FP_B.
        cache.get(FP_A)
        # Insert FP_C — should evict FP_B (oldest accessed_at).
        cache.put(FP_C, sample_result("c"))

        assert cache.get(FP_A) is not None
        assert cache.get(FP_C) is not None
        assert cache.get(FP_B) is None

    def test_stats_reflect_correct_count_after_eviction(self, tmp_path: Path) -> None:
        """stats()['entries'] never exceeds max_entries after eviction."""
        max_e = 3
        cache = AlertCache(make_config(tmp_path, max_entries=max_e))
        fps = [f"{i:064x}" for i in range(6)]  # 6 distinct fingerprints
        for fp in fps:
            cache.put(fp, sample_result(fp))

        assert cache.stats()["entries"] <= max_e

    def test_accessing_entry_updates_lru_position(self, tmp_path: Path) -> None:
        """get() on an entry shifts it to the MRU end so it survives eviction."""
        cache = AlertCache(make_config(tmp_path, max_entries=2))
        cache.put(FP_A, sample_result("a"))
        cache.put(FP_B, sample_result("b"))
        # Access FP_A — it should now be MRU; FP_B becomes LRU.
        cache.get(FP_A)
        # Insert FP_C — FP_B (LRU) should be evicted.
        cache.put(FP_C, sample_result("c"))

        assert cache.get(FP_A) is not None, "FP_A should survive as MRU"
        assert cache.get(FP_B) is None, "FP_B should be evicted as LRU"


# ---------------------------------------------------------------------------
# TestCacheStats
# ---------------------------------------------------------------------------


class TestCacheStats:
    """Four tests covering hit/miss/entry counting via stats()."""

    def test_hits_count_increments_on_each_hit(self, tmp_path: Path) -> None:
        """Each successful get() increments the hits counter by one."""
        cache = AlertCache(make_config(tmp_path))
        cache.put(FP_A, sample_result())
        cache.get(FP_A)
        cache.get(FP_A)
        assert cache.stats()["hits"] == 2

    def test_misses_count_tracks_missed_lookups(self, tmp_path: Path) -> None:
        """Each failed get() increments the misses counter by one."""
        cache = AlertCache(make_config(tmp_path))
        cache.get(FP_A)  # empty cache
        cache.get(FP_B)
        assert cache.stats()["misses"] == 2

    def test_stats_returns_all_expected_keys(self, tmp_path: Path) -> None:
        """stats() dict always contains hits, misses, entries, size_bytes."""
        cache = AlertCache(make_config(tmp_path))
        s = cache.stats()
        assert set(s.keys()) >= {"hits", "misses", "entries", "size_bytes"}

    def test_stats_resets_after_clear(self, tmp_path: Path) -> None:
        """clear() resets in-process hits and misses to zero."""
        cache = AlertCache(make_config(tmp_path))
        cache.put(FP_A, sample_result())
        cache.get(FP_A)   # hit
        cache.get(FP_B)   # miss

        cache.clear()
        s = cache.stats()
        assert s["hits"] == 0
        assert s["misses"] == 0
        assert s["entries"] == 0


# ---------------------------------------------------------------------------
# TestCachePersistence
# ---------------------------------------------------------------------------


class TestCachePersistence:
    """Four tests verifying SQLite durability across process-like restarts."""

    def test_entries_survive_process_restart(self, tmp_path: Path) -> None:
        """A second AlertCache instance over the same db sees stored entries."""
        cfg = make_config(tmp_path)
        cache1 = AlertCache(cfg)
        cache1.put(FP_A, sample_result("persist"))
        cache1.close()

        cache2 = AlertCache(cfg)
        assert cache2.get(FP_A) == sample_result("persist")

    def test_expired_entries_not_returned_after_restart(self, tmp_path: Path) -> None:
        """Expired entries stored by a prior instance are not returned."""
        cfg = make_config(tmp_path, ttl_seconds=1)
        cache1 = AlertCache(cfg)
        cache1.put(FP_A, sample_result())

        # Backdate the entry so it appears expired.
        conn = cache1._get_conn()
        past = (datetime.now(tz=timezone.utc) - timedelta(seconds=10)).isoformat()
        conn.execute(
            "UPDATE cache_entries SET created_at = ? WHERE fingerprint = ?",
            (past, FP_A),
        )
        conn.commit()
        cache1.close()

        cache2 = AlertCache(cfg)
        assert cache2.get(FP_A) is None

    def test_db_file_created_in_correct_location(self, tmp_path: Path) -> None:
        """The SQLite database file is created inside cache_dir as alerts.db."""
        cfg = make_config(tmp_path)
        AlertCache(cfg)
        db_path = cfg.cache_dir / "alerts.db"
        assert db_path.exists(), f"Expected db at {db_path}"

    def test_db_directory_created_with_0o700_permissions(self, tmp_path: Path) -> None:
        """The cache directory is created with mode 0700 (owner-only)."""
        cfg = make_config(tmp_path)
        AlertCache(cfg)
        dir_mode = stat.S_IMODE(cfg.cache_dir.stat().st_mode)
        assert dir_mode == 0o700, f"Expected 0o700, got {oct(dir_mode)}"


# ---------------------------------------------------------------------------
# TestCacheConfig
# ---------------------------------------------------------------------------


class TestCacheConfig:
    """Three tests verifying CacheConfig options are honoured."""

    def test_disabled_cache_always_returns_none(self, tmp_path: Path) -> None:
        """When enabled=False, get() always returns None regardless of put()."""
        cfg = make_config(tmp_path, enabled=False)
        cache = AlertCache(cfg)
        cache.put(FP_A, sample_result())
        assert cache.get(FP_A) is None

    def test_custom_ttl_is_respected(self, tmp_path: Path) -> None:
        """An entry stored longer ago than ttl_seconds is treated as expired."""
        cfg = make_config(tmp_path, ttl_seconds=60)
        cache = AlertCache(cfg)
        cache.put(FP_A, sample_result())

        # Backdate entry by 120 seconds (double the TTL).
        conn = cache._get_conn()
        past = (datetime.now(tz=timezone.utc) - timedelta(seconds=120)).isoformat()
        conn.execute(
            "UPDATE cache_entries SET created_at = ? WHERE fingerprint = ?",
            (past, FP_A),
        )
        conn.commit()

        assert cache.get(FP_A) is None

    def test_custom_max_entries_triggers_eviction_at_correct_threshold(
        self, tmp_path: Path
    ) -> None:
        """Eviction only fires once the entry count reaches max_entries."""
        max_e = 4
        cfg = make_config(tmp_path, max_entries=max_e)
        cache = AlertCache(cfg)

        fps = [f"{i:064x}" for i in range(max_e)]
        for fp in fps:
            cache.put(fp, sample_result(fp))

        # Exactly max_entries stored — no eviction yet.
        assert cache.stats()["entries"] == max_e

        # One more insert must trigger eviction.
        extra_fp = f"{max_e:064x}"
        cache.put(extra_fp, sample_result(extra_fp))
        assert cache.stats()["entries"] == max_e
