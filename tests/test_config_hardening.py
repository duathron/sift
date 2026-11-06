"""Config search path, file permissions, the redaction key rename and config error hygiene."""

from __future__ import annotations

import os
import stat
import warnings
from pathlib import Path

import pytest
import yaml

import sift.cache as cache_mod
import sift.config as config_mod
import sift.version_check as vc_mod
from sift.config import AppConfig, ConfigError, load_config, save_config, save_credentials, save_ticket_token


@pytest.fixture
def app_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "home" / ".sift"
    monkeypatch.setattr(config_mod, "_APP_DIR", d)
    monkeypatch.delenv("SIFT_LLM_KEY", raising=False)
    return d


def _mode(p: Path) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


# --- search path -----------------------------------------------------------


def test_cwd_config_is_NOT_loaded(app_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "config.yaml").write_text(
        yaml.dump(
            {
                "injection": {"whitelist_patterns": [".*"]},
                "ticketing": {"url": "https://attacker.example"},
            }
        )
    )
    monkeypatch.chdir(work)
    cfg = load_config()
    assert cfg.injection.whitelist_patterns == []
    assert cfg.ticketing.url is None


def test_explicit_config_still_works(app_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    explicit = work / "config.yaml"
    explicit.write_text(yaml.dump({"ticketing": {"url": "https://ticket.example"}}))
    assert load_config(config_path=explicit).ticketing.url == "https://ticket.example"


# --- directory and .env permissions ----------------------------------------


def test_cache_creates_sift_root_0700(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "fresh-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    old = os.umask(0o022)
    try:
        cache = cache_mod.AlertCache(cache_mod.CacheConfig(enabled=True, cache_dir=home / ".sift" / "cache"))
        cache.put("a" * 64, {"k": 1})
    finally:
        os.umask(old)
    assert _mode(home / ".sift") == 0o700
    assert _mode(home / ".sift" / "cache") == 0o700


def test_cache_hardens_preexisting_loose_sift_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "old-home"
    (home / ".sift").mkdir(parents=True)
    os.chmod(home / ".sift", 0o755)
    monkeypatch.setenv("HOME", str(home))
    cache_mod.AlertCache(cache_mod.CacheConfig(enabled=True, cache_dir=home / ".sift" / "cache")).put("b" * 64, {})
    assert _mode(home / ".sift") == 0o700


def test_version_check_hardens_sift_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "vc-home"
    (home / ".sift").mkdir(parents=True)
    os.chmod(home / ".sift", 0o755)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(vc_mod, "_CACHE_FILE", home / ".sift" / "version_check.json")
    vc_mod._save_cache({"x": 1})
    assert _mode(home / ".sift") == 0o700


def test_ensure_app_dir_hardens_loose_dir(app_dir: Path) -> None:
    app_dir.mkdir(parents=True)
    os.chmod(app_dir, 0o755)
    config_mod._ensure_app_dir()
    assert _mode(app_dir) == 0o700


def test_save_credentials_never_world_readable_at_any_instant(app_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The late chmod must not be what does the work: disable it and require 0600 anyway.
    monkeypatch.setattr(Path, "chmod", lambda self, mode, **kw: None)
    old = os.umask(0o022)
    try:
        env = save_credentials("sk-secret")
        tok = save_ticket_token("tk-secret", "thehive")
    finally:
        os.umask(old)
    assert _mode(env) == 0o600
    assert _mode(tok) == 0o600


def test_save_credentials_hardens_preexisting_0644_env(app_dir: Path) -> None:
    app_dir.mkdir(parents=True)
    env = app_dir / ".env"
    env.write_text("OTHER=1\n")
    os.chmod(env, 0o644)
    save_credentials("sk-secret")
    assert _mode(env) == 0o600
    assert "OTHER=1" in env.read_text()
    assert "SIFT_LLM_KEY=sk-secret" in env.read_text()


def test_clear_credentials_keeps_0600(app_dir: Path) -> None:
    env = save_credentials("sk-secret")
    os.chmod(env, 0o644)
    assert config_mod.clear_credentials() is True
    assert _mode(env) == 0o600
    assert "sk-secret" not in env.read_text()


def test_save_config_creates_0600(app_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "chmod", lambda self, mode, **kw: None)
    old = os.umask(0o022)
    try:
        path = save_config(AppConfig())
    finally:
        os.umask(old)
    assert _mode(path) == 0o600


def test_env_symlink_refused(app_dir: Path) -> None:
    app_dir.mkdir(parents=True)
    target = app_dir.parent / "victim.txt"
    target.write_text("untouched\n")
    (app_dir / ".env").symlink_to(target)
    with pytest.raises(OSError):
        save_credentials("sk-secret")
    assert target.read_text() == "untouched\n"
    assert (app_dir / ".env").is_symlink()


# --- redaction.keep_raw (formerly redact_raw) -----------------------------


@pytest.fixture
def _fresh_legacy_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod, "_LEGACY_REDACT_RAW_WARNED", False)


def test_legacy_redact_raw_true_maps_to_keep_raw(_fresh_legacy_warning: None) -> None:
    with pytest.warns(FutureWarning):
        cfg = config_mod.AlertRedactionConfig(redact_raw=True)
    assert cfg.keep_raw is True
    assert cfg.redact_raw is True


def test_keep_raw_default_and_conflict_keep_raw_wins(_fresh_legacy_warning: None) -> None:
    assert config_mod.AlertRedactionConfig().keep_raw is False
    with pytest.warns(FutureWarning):
        cfg = config_mod.AlertRedactionConfig(keep_raw=False, redact_raw=True)
    assert cfg.keep_raw is False


def test_keep_raw_roundtrip_via_save_config(app_dir: Path) -> None:
    cfg = AppConfig()
    cfg.redaction.keep_raw = True
    path = save_config(cfg)
    on_disk = yaml.safe_load(path.read_text())
    assert on_disk["redaction"]["keep_raw"] is True
    assert "redact_raw" not in on_disk["redaction"]
    assert load_config(path).redaction.keep_raw is True


def test_legacy_yaml_key_loaded_from_config_file(app_dir: Path, tmp_path: Path, _fresh_legacy_warning: None) -> None:
    f = tmp_path / "legacy.yaml"
    f.write_text(yaml.dump({"redaction": {"redact_raw": True}}))
    with pytest.warns(FutureWarning):
        assert load_config(f).redaction.keep_raw is True


def test_redact_raw_deprecation_warns_once(_fresh_legacy_warning: None) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        config_mod.AlertRedactionConfig(redact_raw=True)
        config_mod.AlertRedactionConfig(redact_raw=True)
    assert len([w for w in caught if issubclass(w.category, FutureWarning)]) == 1


def test_new_key_does_not_warn(_fresh_legacy_warning: None) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        config_mod.AlertRedactionConfig(keep_raw=True)


# --- value-free config errors, no locals in tracebacks ----------------------


def test_yaml_error_is_value_free(app_dir: Path, tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("summarize:\n  api_key: sk-LEAKME-123\n  : [unclosed\n")
    with pytest.raises(ConfigError) as ei:
        load_config(f)
    assert "sk-LEAKME" not in str(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


@pytest.mark.parametrize("text", ["- sk-LEAKME-123\n", "sk-LEAKME-123\n", "42\n"])
def test_non_mapping_config_is_value_free(app_dir: Path, tmp_path: Path, text: str) -> None:
    f = tmp_path / "list.yaml"
    f.write_text(text)
    with pytest.raises(ConfigError) as ei:
        load_config(f)
    assert "sk-LEAKME" not in str(ei.value)


def test_schema_error_is_value_free(app_dir: Path, tmp_path: Path) -> None:
    f = tmp_path / "wrongtype.yaml"
    f.write_text(yaml.dump({"clustering": {"time_window_minutes": "sk-LEAKME-123"}}))
    with pytest.raises(ConfigError) as ei:
        load_config(f)
    assert "sk-LEAKME" not in str(ei.value)
    assert "time_window_minutes" in str(ei.value)


def test_cli_hides_locals_in_tracebacks() -> None:
    from sift.main import app

    assert app.pretty_exceptions_show_locals is False
