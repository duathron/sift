"""Characterization tests for sift.config.load_config.

These lock in the CURRENT behavior of the config loader so it can be
refactored onto shipwright_kit.config without changing behavior. They cover:
  (a) defaults when no config file exists,
  (b) an explicit config_path wins over other candidates,
  (c) ~/.sift/config.yaml is used when present,
  (d) ./config.yaml is the fallback,
  (e) the SIFT_LLM_KEY env var overrides summarize.api_key,
  (f) a ~/.sift/.env containing SIFT_LLM_KEY=... is honored (dotenv load).

NOTE: ``_APP_DIR`` is bound at import time (``Path.home() / ".sift"``), so the
loader references the module-level ``sift.config._APP_DIR``. Monkeypatching
``Path.home()`` alone does NOT redirect it — we monkeypatch
``sift.config._APP_DIR`` directly (mirrors barb's tests).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sift import config as config_mod
from sift.config import AppConfig, load_config


@pytest.fixture
def app_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the module-level _APP_DIR to a temp dir and clear SIFT_LLM_KEY."""
    d = tmp_path / ".sift"
    d.mkdir()
    monkeypatch.setattr(config_mod, "_APP_DIR", d)
    monkeypatch.delenv("SIFT_LLM_KEY", raising=False)
    return d


def test_defaults_when_no_file(app_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No config.yaml anywhere (cwd has none either).
    monkeypatch.chdir(tmp_path)
    cfg = load_config()
    assert isinstance(cfg, AppConfig)
    # Spot-check a few defaults from the schema.
    assert cfg.summarize.provider == "template"
    assert cfg.summarize.api_key is None
    assert cfg.clustering.time_window_minutes == 30
    assert cfg.cache_enabled is True


def test_explicit_path_wins(app_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ~/.sift/config.yaml and ./config.yaml both present, but explicit path wins.
    (app_dir / "config.yaml").write_text(yaml.dump({"summarize": {"provider": "anthropic"}}))
    monkeypatch.chdir(tmp_path)
    Path("config.yaml").write_text(yaml.dump({"summarize": {"provider": "openai"}}))

    explicit = tmp_path / "explicit.yaml"
    explicit.write_text(yaml.dump({"summarize": {"provider": "ollama"}}))

    cfg = load_config(config_path=explicit)
    assert cfg.summarize.provider == "ollama"


def test_app_dir_config_used(app_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ~/.sift/config.yaml present, no explicit path; cwd has no config.yaml.
    (app_dir / "config.yaml").write_text(yaml.dump({"clustering": {"time_window_minutes": 99}}))
    monkeypatch.chdir(tmp_path)
    cfg = load_config()
    assert cfg.clustering.time_window_minutes == 99


def test_cwd_config_fallback(app_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No explicit path, no ~/.sift/config.yaml -> ./config.yaml is the fallback.
    monkeypatch.chdir(tmp_path)
    Path("config.yaml").write_text(yaml.dump({"output": {"default_format": "json"}}))
    cfg = load_config()
    assert cfg.output.default_format == "json"


def test_sift_llm_key_env_override(app_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # SIFT_LLM_KEY env var overrides summarize.api_key.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SIFT_LLM_KEY", "sk-from-env")
    cfg = load_config()
    assert cfg.summarize.api_key == "sk-from-env"


def test_dotenv_in_app_dir_honored(app_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A ~/.sift/.env with SIFT_LLM_KEY=... is loaded and flows into summarize.api_key.
    monkeypatch.chdir(tmp_path)
    (app_dir / ".env").write_text("SIFT_LLM_KEY=sk-from-dotenv\n")
    cfg = load_config()
    assert cfg.summarize.api_key == "sk-from-dotenv"
