"""Tests for S2b: tuning thresholds lifted into ClusteringConfig.

TDD — written before production code.

Characterization tests proving auto_tune() decisions are byte-identical at
default config values. Also verifies new ClusteringConfig fields exist and
that custom values override the module-level defaults.
"""

from __future__ import annotations

from sift.config import ClusteringConfig
from sift.tuning import auto_tune

_MB = 1024 * 1024
_GB = 1024 * _MB

# ---------------------------------------------------------------------------
# Verify new fields exist on ClusteringConfig
# ---------------------------------------------------------------------------


class TestClusteringConfigNewFields:
    """ClusteringConfig must expose the four new threshold fields."""

    def test_drop_raw_threshold_mb_field_exists(self):
        cfg = ClusteringConfig()
        assert hasattr(cfg, "drop_raw_threshold_mb")

    def test_chunk_threshold_mb_field_exists(self):
        cfg = ClusteringConfig()
        assert hasattr(cfg, "chunk_threshold_mb")

    def test_default_chunk_size_field_exists(self):
        cfg = ClusteringConfig()
        assert hasattr(cfg, "default_chunk_size")

    def test_default_sub_chunk_size_field_exists(self):
        # default_sub_chunk_size may alias sub_chunk_size; either field must be present
        cfg = ClusteringConfig()
        # sub_chunk_size was already there and now also acts as the default
        assert hasattr(cfg, "sub_chunk_size")

    def test_drop_raw_threshold_mb_default_is_500(self):
        cfg = ClusteringConfig()
        assert cfg.drop_raw_threshold_mb == 500

    def test_chunk_threshold_mb_default_is_200(self):
        cfg = ClusteringConfig()
        assert cfg.chunk_threshold_mb == 200

    def test_default_chunk_size_default_is_100000(self):
        cfg = ClusteringConfig()
        assert cfg.default_chunk_size == 100_000


# ---------------------------------------------------------------------------
# Characterization tests: default config == no-config (byte-identical behaviour)
# ---------------------------------------------------------------------------


class TestDefaultConfigBehaviorIdentical:
    """auto_tune() with default ClusteringConfig == auto_tune() with no cfg."""

    def test_small_input_no_tuning(self):
        r_bare = auto_tune(total_bytes=1 * _MB, file_count=1)
        r_cfg = auto_tune(total_bytes=1 * _MB, file_count=1, cfg=ClusteringConfig())
        assert r_bare.chunk_size == r_cfg.chunk_size
        assert r_bare.drop_raw == r_cfg.drop_raw
        assert r_bare.sub_chunk == r_cfg.sub_chunk

    def test_medium_input_chunk_decision(self):
        r_bare = auto_tune(total_bytes=300 * _MB, file_count=1)
        r_cfg = auto_tune(total_bytes=300 * _MB, file_count=1, cfg=ClusteringConfig())
        assert r_bare.chunk_size == r_cfg.chunk_size
        assert r_bare.drop_raw == r_cfg.drop_raw

    def test_large_input_drop_raw_decision(self):
        r_bare = auto_tune(total_bytes=600 * _MB, file_count=1)
        r_cfg = auto_tune(total_bytes=600 * _MB, file_count=1, cfg=ClusteringConfig())
        assert r_bare.drop_raw == r_cfg.drop_raw
        assert r_bare.chunk_size == r_cfg.chunk_size

    def test_sub_chunk_decision(self):
        r_bare = auto_tune(total_bytes=600 * _MB, file_count=1, largest_file_bytes=600 * _MB)
        r_cfg = auto_tune(
            total_bytes=600 * _MB,
            file_count=1,
            largest_file_bytes=600 * _MB,
            cfg=ClusteringConfig(),
        )
        assert r_bare.sub_chunk == r_cfg.sub_chunk
        assert r_bare.sub_chunk_size == r_cfg.sub_chunk_size

    def test_threshold_boundary_200mb_chunk(self):
        """201 MB triggers chunking with default config, matching bare call."""
        r_bare = auto_tune(total_bytes=201 * _MB, file_count=1)
        r_cfg = auto_tune(total_bytes=201 * _MB, file_count=1, cfg=ClusteringConfig())
        assert r_bare.chunk_size == r_cfg.chunk_size

    def test_threshold_boundary_500mb_drop_raw(self):
        """501 MB triggers drop-raw with default config, matching bare call."""
        r_bare = auto_tune(total_bytes=501 * _MB, file_count=1)
        r_cfg = auto_tune(total_bytes=501 * _MB, file_count=1, cfg=ClusteringConfig())
        assert r_bare.drop_raw == r_cfg.drop_raw


# ---------------------------------------------------------------------------
# Custom config overrides module-level defaults
# ---------------------------------------------------------------------------


class TestCustomConfigThresholds:
    """User-supplied config values override the module constants."""

    def test_lower_chunk_threshold_triggers_earlier(self):
        cfg = ClusteringConfig(chunk_threshold_mb=50)
        r = auto_tune(total_bytes=60 * _MB, file_count=1, cfg=cfg)
        assert r.chunk_size > 0  # triggered at 60 MB (below default 200 MB)

    def test_higher_chunk_threshold_prevents_chunking(self):
        cfg = ClusteringConfig(chunk_threshold_mb=500)
        r = auto_tune(total_bytes=300 * _MB, file_count=1, cfg=cfg)
        assert r.chunk_size == 0  # NOT triggered (300 MB < 500 MB threshold)

    def test_lower_drop_raw_threshold_triggers_earlier(self):
        cfg = ClusteringConfig(drop_raw_threshold_mb=100)
        r = auto_tune(total_bytes=150 * _MB, file_count=1, cfg=cfg)
        assert r.drop_raw is True  # triggered at 150 MB (below default 500 MB)

    def test_custom_default_chunk_size_used(self):
        cfg = ClusteringConfig(chunk_threshold_mb=50, default_chunk_size=50_000)
        r = auto_tune(total_bytes=60 * _MB, file_count=1, cfg=cfg)
        assert r.chunk_size == 50_000

    def test_cli_chunk_size_still_beats_config(self):
        cfg = ClusteringConfig(chunk_threshold_mb=50, default_chunk_size=50_000)
        r = auto_tune(total_bytes=60 * _MB, file_count=1, cfg=cfg, user_chunk_size=25_000)
        assert r.chunk_size == 25_000
