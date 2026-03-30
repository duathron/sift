"""Tests for sift.tuning — auto-tuning engine."""

from __future__ import annotations

import pytest

from sift.config import ClusteringConfig
from sift.tuning import TuneResult, auto_tune

_MB = 1024 * 1024
_GB = 1024 * _MB


class TestAutoTuneSmallInput:
    """Input below all thresholds — no tuning."""

    def test_tiny_file(self):
        r = auto_tune(total_bytes=1 * _MB, file_count=1)
        assert r.drop_raw is False
        assert r.chunk_size == 0
        assert r.sub_chunk is False

    def test_10mb_file(self):
        r = auto_tune(total_bytes=10 * _MB, file_count=1)
        assert r.drop_raw is False
        assert r.chunk_size == 0

    def test_49mb_file(self):
        r = auto_tune(total_bytes=49 * _MB, file_count=1)
        assert r.drop_raw is False
        assert r.chunk_size == 0

    def test_reason_says_no_tuning(self):
        r = auto_tune(total_bytes=1 * _MB, file_count=1)
        assert "no tuning" in r.reason.lower()


class TestAutoTuneMediumInput:
    """Input above chunk threshold but below drop-raw threshold."""

    def test_300mb_enables_chunking(self):
        r = auto_tune(total_bytes=300 * _MB, file_count=1)
        assert r.chunk_size == 100_000
        assert r.drop_raw is False

    def test_200mb_exactly_triggers_chunking(self):
        r = auto_tune(total_bytes=201 * _MB, file_count=1)
        assert r.chunk_size > 0


class TestAutoTuneLargeInput:
    """Input above drop-raw threshold."""

    def test_500mb_enables_drop_raw(self):
        r = auto_tune(total_bytes=501 * _MB, file_count=1)
        assert r.drop_raw is True
        assert r.chunk_size > 0

    def test_1gb_enables_drop_raw_and_chunking(self):
        r = auto_tune(total_bytes=1 * _GB, file_count=1)
        assert r.drop_raw is True
        assert r.chunk_size == 100_000

    def test_10gb(self):
        r = auto_tune(total_bytes=10 * _GB, file_count=5)
        assert r.drop_raw is True
        assert r.chunk_size == 100_000

    def test_22gb(self):
        r = auto_tune(total_bytes=22 * _GB, file_count=10)
        assert r.drop_raw is True
        assert r.chunk_size == 100_000


class TestSubFileChunking:
    """Sub-file chunking for individual large files."""

    def test_small_file_no_sub_chunk(self):
        r = auto_tune(total_bytes=400 * _MB, file_count=1, largest_file_bytes=400 * _MB)
        assert r.sub_chunk is False

    def test_600mb_file_triggers_sub_chunk(self):
        r = auto_tune(total_bytes=600 * _MB, file_count=1, largest_file_bytes=600 * _MB)
        assert r.sub_chunk is True
        assert r.sub_chunk_size == 100_000

    def test_2gb_file_triggers_sub_chunk(self):
        r = auto_tune(total_bytes=2 * _GB, file_count=1, largest_file_bytes=2 * _GB)
        assert r.sub_chunk is True

    def test_total_large_but_individual_files_small(self):
        """Many small files totaling 2GB should NOT trigger sub-chunking."""
        r = auto_tune(total_bytes=2 * _GB, file_count=100, largest_file_bytes=20 * _MB)
        assert r.sub_chunk is False


class TestUserOverrides:
    """Explicit CLI flags always win over auto-tuning."""

    def test_user_chunk_size_overrides(self):
        r = auto_tune(total_bytes=1 * _GB, file_count=1, user_chunk_size=50_000)
        assert r.chunk_size == 50_000

    def test_user_drop_raw_false_overrides(self):
        """User explicitly says --no-drop-raw (or doesn't set --drop-raw)."""
        r = auto_tune(total_bytes=1 * _GB, file_count=1, user_drop_raw=False)
        assert r.drop_raw is False

    def test_user_drop_raw_true_on_small_input(self):
        r = auto_tune(total_bytes=10 * _MB, file_count=1, user_drop_raw=True)
        assert r.drop_raw is True

    def test_user_chunk_size_zero_means_no_chunking(self):
        """--chunk-size 0 explicitly disables chunking."""
        # user_chunk_size=0 means "not set" (falsy), auto-tune kicks in
        r = auto_tune(total_bytes=1 * _GB, file_count=1, user_chunk_size=0)
        assert r.chunk_size == 100_000  # auto-tune

    def test_user_chunk_size_positive_overrides(self):
        r = auto_tune(total_bytes=10 * _MB, file_count=1, user_chunk_size=25_000)
        assert r.chunk_size == 25_000


class TestConfigOverrides:
    """Config.yaml values are respected when no CLI flag is set."""

    def test_config_chunk_size(self):
        cfg = ClusteringConfig(chunk_size=50_000)
        r = auto_tune(total_bytes=10 * _MB, file_count=1, cfg=cfg)
        assert r.chunk_size == 50_000

    def test_user_flag_beats_config(self):
        cfg = ClusteringConfig(chunk_size=50_000)
        r = auto_tune(total_bytes=10 * _MB, file_count=1, cfg=cfg, user_chunk_size=25_000)
        assert r.chunk_size == 25_000

    def test_config_sub_chunk_threshold(self):
        cfg = ClusteringConfig(sub_chunk_threshold_mb=200)
        r = auto_tune(total_bytes=300 * _MB, file_count=1, largest_file_bytes=300 * _MB, cfg=cfg)
        assert r.sub_chunk is True  # 300 MB > 200 MB threshold

    def test_config_sub_chunk_size(self):
        cfg = ClusteringConfig(sub_chunk_threshold_mb=200, sub_chunk_size=50_000)
        r = auto_tune(total_bytes=300 * _MB, file_count=1, largest_file_bytes=300 * _MB, cfg=cfg)
        assert r.sub_chunk_size == 50_000


class TestTuneResultImmutable:
    """TuneResult is frozen dataclass."""

    def test_frozen(self):
        r = auto_tune(total_bytes=1 * _MB, file_count=1)
        with pytest.raises(AttributeError):
            r.chunk_size = 999  # type: ignore[misc]

    def test_reason_is_string(self):
        r = auto_tune(total_bytes=1 * _GB, file_count=3, largest_file_bytes=600 * _MB)
        assert isinstance(r.reason, str)
        assert len(r.reason) > 0
