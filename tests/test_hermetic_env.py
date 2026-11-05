"""The suite must never read or write the operator's real ``~/.sift``."""

import os
import pwd
from pathlib import Path

import sift.cache
import sift.config


def test_hermetic_env(tmp_path: Path) -> None:
    real_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    test_home = Path(os.environ["HOME"]).resolve()

    # HOME is a per-session throwaway directory, not the real home.
    assert test_home != real_home
    assert not test_home.is_relative_to(real_home)
    assert test_home.name.startswith("sift-test-home-")
    assert Path.home().resolve() == test_home

    # Import-time bound paths resolve under the throwaway HOME.
    assert sift.config._APP_DIR.resolve().is_relative_to(test_home)

    # The default cache dir is per test (tmp_path), never ~/.sift/cache.
    default_cache = sift.cache.CacheConfig(enabled=True).cache_dir
    assert default_cache == tmp_path / "cache"
