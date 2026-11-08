"""Round 6: every up-front refusal happens before the first write; two mutant pins.

Companion to ``test_config_round5.py``. Everything runs against a throwaway HOME.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

import sift.config as config_mod
import sift.doctor as doctor_mod
from sift.main import app

SECRET = "sk-ant-FAKESECRET"
BIDI = "‮"


@pytest.fixture(autouse=True)
def _wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "1000")


def _point_home(h: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setattr(config_mod, "_APP_DIR", h / ".sift")
    monkeypatch.setattr(doctor_mod, "CONFIG_PATH", h / ".sift" / "config.yaml")
    monkeypatch.setattr(doctor_mod, "OUTPUT_DIR", h / ".sift")
    monkeypatch.setattr(doctor_mod, "CACHE_DIR", h / ".sift" / "cache")
    monkeypatch.delenv("SIFT_LLM_KEY", raising=False)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    (h / ".sift").mkdir(parents=True)
    _point_home(h, monkeypatch)
    return h


# ---------------------------------------------------------------------------
# 1. --ticket-token without a provider is refused before anything is saved
# ---------------------------------------------------------------------------


def test_ticket_token_without_provider_writes_nothing(home: Path) -> None:
    result = CliRunner().invoke(app, ["config", "--ticket-token", "T-FAKE", "--quiet"])
    assert result.exit_code == 2, (result.stdout, result.stderr, result.exception)
    assert "--ticket-token requires --ticket-provider" in result.stdout + result.stderr
    assert not (home / ".sift" / "config.yaml").exists()
    assert not (home / ".sift" / ".env").exists()


def test_ticket_token_without_provider_with_api_key_writes_nothing(home: Path) -> None:
    result = CliRunner().invoke(app, ["config", "--api-key", SECRET, "--ticket-token", "T-FAKE"])
    assert result.exit_code == 2, (result.stdout, result.stderr, result.exception)
    assert not (home / ".sift" / "config.yaml").exists()
    assert not (home / ".sift" / ".env").exists()


def test_ticket_token_with_a_provider_still_saves(home: Path) -> None:
    result = CliRunner().invoke(app, ["config", "--ticket-provider", "thehive", "--ticket-token", "T-FAKE"])
    assert result.exit_code == 0, (result.stdout, result.stderr, result.exception)
    assert "SIFT_THEHIVE_TOKEN=T-FAKE" in (home / ".sift" / ".env").read_text()
    assert (home / ".sift" / "config.yaml").exists()


# ---------------------------------------------------------------------------
# 2. an unusable credentials target is refused before the config is saved
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["--provider", "mock", "--api-key", SECRET],
        ["--provider", "mock", "--unset-api-key"],
        ["--ticket-provider", "thehive", "--ticket-token", "T-FAKE"],
    ],
)
@pytest.mark.parametrize("config_existed", [False, True])
def test_symlinked_credentials_file_leaves_config_untouched(
    args: list[str], config_existed: bool, home: Path, tmp_path: Path
) -> None:
    victim = tmp_path / "victim.env"
    victim.write_text("VICTIM=1\n")
    (home / ".sift" / ".env").symlink_to(victim)
    cfg = home / ".sift" / "config.yaml"
    if config_existed:
        cfg.write_text("summarize:\n  provider: template\n")
    before = cfg.read_bytes() if config_existed else None
    result = CliRunner().invoke(app, ["config", *args])
    assert result.exit_code == 2, (result.stdout, result.stderr, result.exception)
    assert "cannot write credentials file" in result.stderr
    assert (cfg.read_bytes() if cfg.exists() else None) == before
    assert victim.read_text() == "VICTIM=1\n"


@pytest.mark.parametrize("kind", ["dangling", "directory", "fifo"])
def test_check_credentials_target_refuses_every_non_regular_leaf(kind: str, tmp_path: Path) -> None:
    target = tmp_path / ".env"
    if kind == "dangling":
        target.symlink_to(tmp_path / "nowhere")
    elif kind == "directory":
        target.mkdir()
    else:
        os.mkfifo(target)
    with pytest.raises(config_mod.ConfigError, match="cannot write credentials file"):
        config_mod.check_credentials_target(target)


def test_check_credentials_target_accepts_absent_and_regular(tmp_path: Path) -> None:
    config_mod.check_credentials_target(tmp_path / ".env")
    (tmp_path / ".env").write_text("A=1\n")
    config_mod.check_credentials_target(tmp_path / ".env")


def test_a_credentials_write_failing_after_the_precheck_keeps_the_config_change(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_key: str) -> Path:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("sift.config.save_credentials", boom)
    result = CliRunner().invoke(app, ["config", "--provider", "mock", "--api-key", SECRET])
    assert result.exit_code == 2
    assert "provider: mock" in (home / ".sift" / "config.yaml").read_text()
    assert SECRET not in result.stdout + result.stderr


# ---------------------------------------------------------------------------
# 3. a read-only config directory is still refused, now by the write itself
# ---------------------------------------------------------------------------


def test_read_only_config_directory_is_refused_and_no_credential_is_written(home: Path, tmp_path: Path) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        result = CliRunner().invoke(
            app, ["config", "--provider", "mock", "--api-key", SECRET, "--config", str(ro / "c.yaml")]
        )
    finally:
        ro.chmod(0o700)
    assert result.exit_code == 2, (result.stderr, result.exception)
    assert "cannot write config" in result.stderr
    assert not (home / ".sift" / ".env").exists()


# ---------------------------------------------------------------------------
# 4. mutant pins
# ---------------------------------------------------------------------------


def test_invalid_entry_message_shows_the_escaped_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = tmp_path / f"ho{BIDI}me\x1b[31mx"
    (h / ".sift").mkdir(parents=True)
    _point_home(h, monkeypatch)
    (h / ".sift" / ".env").write_text(f"A=\x00tail\nSIFT_LLM_KEY={SECRET}\n")
    result = CliRunner().invoke(app, ["config", "--show"])
    assert result.exit_code == 2, (result.stdout, result.stderr, result.exception)
    assert "contains an invalid entry" in result.stderr
    assert "\\u202e" in result.stderr and "\\x1b" in result.stderr
    assert BIDI not in result.stderr and "\x1b" not in result.stderr
    assert SECRET not in result.stdout + result.stderr


@pytest.mark.skipif(not config_mod._DIR_FD_OK, reason="path-based fallback names its temp file differently")
def test_temp_file_name_has_sixteen_hex_digits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    real_replace = os.replace

    def spy(src, dst, **kw):
        seen.append(str(src))
        return real_replace(src, dst, **kw)

    monkeypatch.setattr(config_mod.os, "replace", spy)
    config_mod._write_private(tmp_path / "c.yaml", "a: 1\n")
    assert len(seen) == 1 and re.fullmatch(r"\.sift-[0-9a-f]{16}\.tmp", seen[0]), seen
