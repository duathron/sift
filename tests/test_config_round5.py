"""Round 5: invalid credentials entries, long config names, emoji shortcodes, mutant pins.

Companion to ``test_config_round4.py``. Everything runs against a throwaway HOME.
"""

from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import sift.config as config_mod
import sift.doctor as doctor_mod
from sift.main import app

SECRET = "sk-ant-FAKESECRET"


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


def _console_script() -> str:
    script = Path(sys.executable).with_name("sift")
    assert script.exists(), script
    return str(script)


def _run_real(args: list[str], home: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    """The installed console script in a fresh process with a throwaway HOME."""
    return subprocess.run(
        [_console_script(), *args],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(home), "COLUMNS": "1000"},
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# 1. a credentials entry that cannot enter the environment is one line, exit 2
# ---------------------------------------------------------------------------

BAD_ENTRIES = {
    "nul-value": f"A=\x00tail\nSIFT_LLM_KEY={SECRET}\n",
    "nul-key": f"K\x00X=v\nSIFT_LLM_KEY={SECRET}\n",
    "illegal-name": f"'K=Z'=v\nSIFT_LLM_KEY={SECRET}\n",
}


@pytest.mark.parametrize("entry", sorted(BAD_ENTRIES))
@pytest.mark.parametrize("command", ["triage", "validate", "metrics", "config"])
def test_invalid_credentials_entry_is_one_line_exit_2(command: str, entry: str, tmp_path: Path) -> None:
    h = tmp_path / "home"
    (h / ".sift").mkdir(parents=True)
    (h / ".sift" / ".env").write_text(BAD_ENTRIES[entry])
    alerts = tmp_path / "a.json"
    alerts.write_text("[]")
    argv = ["config", "--show"] if command == "config" else [command, str(alerts)]
    res = _run_real(argv, h)
    assert res.returncode == 2, (res.stdout, res.stderr)
    assert "Traceback" not in res.stderr and "Error:" not in res.stderr
    lines = res.stderr.strip().splitlines()
    assert len(lines) == 1, res.stderr
    assert lines[0].startswith("sift: credentials file ") and lines[0].endswith("contains an invalid entry")
    assert SECRET not in res.stdout + res.stderr


def test_load_credentials_wraps_a_value_error_from_the_environment(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (home / ".sift" / ".env").write_text("A=1\n")
    monkeypatch.setattr(config_mod, "read_credentials", lambda _p: {"A\x00": "v"})
    with pytest.raises(config_mod.ConfigError, match="contains an invalid entry") as ei:
        config_mod._load_credentials_file(home / ".sift" / ".env")
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


def test_doctor_has_no_traceback_for_a_nul_entry_and_keeps_its_fail_rows(tmp_path: Path) -> None:
    h = tmp_path / "home"
    (h / ".sift").mkdir(parents=True)
    (h / ".sift" / ".env").write_text(BAD_ENTRIES["nul-value"])
    res = _run_real(["doctor"], h)
    assert "Traceback" not in res.stdout + res.stderr
    (h / ".sift" / ".env").write_bytes(b"SIFT_LLM_KEY=\xff\xfe\n")
    res = _run_real(["doctor"], h)
    assert "Traceback" not in res.stdout + res.stderr
    rows = [ln for ln in res.stdout.splitlines() if "not valid UTF-8" in ln]
    assert rows and all("FAIL" in ln for ln in rows), res.stdout


# ---------------------------------------------------------------------------
# 2. a temp name that does not depend on the target; config before credentials
# ---------------------------------------------------------------------------


def _name(length: int) -> str:
    return "n" * (length - len(".yaml")) + ".yaml"


@pytest.mark.parametrize("length", [200, 233, 234, 240, 255])
@pytest.mark.parametrize("dir_fd", [True, False])
def test_write_private_works_for_any_legal_target_name(
    length: int, dir_fd: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config_mod, "_DIR_FD_OK", dir_fd)
    target = tmp_path / _name(length)
    assert len(target.name.encode()) == length
    config_mod._write_private(target, "a: 1\n")
    config_mod._write_private(target, "a: 2\n")  # an existing long-named file can be updated too
    assert target.read_text() == "a: 2\n" and stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == [target.name]


@pytest.mark.parametrize("length", [233, 234, 255])
def test_long_config_name_with_an_api_key_saves_both_or_writes_nothing(length: int, home: Path, tmp_path: Path) -> None:
    target = tmp_path / _name(length)
    res = _run_real(["config", "--api-key", SECRET, "--provider", "mock", "--config", str(target)], home)
    env = home / ".sift" / ".env"
    if res.returncode == 0:
        assert target.is_file() and SECRET in env.read_text()
    else:
        assert res.returncode == 2 and not env.exists() and not target.exists(), res.stderr
    assert res.returncode == 0, res.stderr  # with the short temp name the save succeeds
    assert not any(p.name.endswith(".tmp") for p in tmp_path.iterdir())


def test_a_config_save_failure_after_the_check_leaves_no_credential(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a, **_k):
        raise OSError(errno.ENOSPC, "full")

    monkeypatch.setattr(config_mod, "save_config", boom)
    res = CliRunner().invoke(app, ["config", "--api-key", SECRET, "--provider", "mock"])
    assert res.exit_code == 2, (res.stderr, res.exception)
    assert not (home / ".sift" / ".env").exists()
    res = CliRunner().invoke(app, ["config", "--ticket-provider", "thehive", "--ticket-token", "tok", "--model", "m"])
    assert res.exit_code == 2
    assert not (home / ".sift" / ".env").exists()


def test_config_is_saved_before_the_credentials(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    real_write = config_mod._write_private

    def spy(path: Path, text: str) -> None:
        order.append(path.name)
        real_write(path, text)

    monkeypatch.setattr(config_mod, "_write_private", spy)
    res = CliRunner().invoke(app, ["config", "--api-key", SECRET, "--provider", "mock"])
    assert res.exit_code == 0, (res.stderr, res.exception)
    assert order == ["config.yaml", ".env"]


def test_fallback_refuses_a_fifo_leaf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod, "_DIR_FD_OK", False)
    target = tmp_path / "c.yaml"
    os.mkfifo(target)
    with pytest.raises(OSError):
        config_mod._write_private(target, "a: 1\n")
    assert stat.S_ISFIFO(os.lstat(target).st_mode) and [p.name for p in tmp_path.iterdir()] == ["c.yaml"]


# ---------------------------------------------------------------------------
# 3. Rich emoji shortcodes in a path stay literal
# ---------------------------------------------------------------------------

SHORTCODES = [":skull:", ":warning:"]


@pytest.mark.parametrize("code", SHORTCODES)
def test_saved_paths_keep_emoji_shortcodes_literal(code: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = tmp_path / f"H{code}x"
    (h / ".sift").mkdir(parents=True)
    _point_home(h, monkeypatch)
    key = CliRunner().invoke(app, ["config", "--api-key", SECRET])
    assert key.exit_code == 0, (key.stderr, key.exception)
    tok = CliRunner().invoke(app, ["config", "--ticket-provider", "thehive", "--ticket-token", "t"])
    assert tok.exit_code == 0, (tok.stderr, tok.exception)
    new = CliRunner().invoke(app, ["config", "--provider", "mock", "--config", str(tmp_path / f"c{code}.yaml")])
    again = CliRunner().invoke(app, ["config", "--provider", "template", "--config", str(tmp_path / f"c{code}.yaml")])
    for res, needle in ((key, "API key saved to"), (tok, "Ticket token saved to")):
        line = next(ln for ln in res.stderr.splitlines() if needle in ln)
        assert code in line, line
    assert code in next(ln for ln in new.stderr.splitlines() if "created new config" in ln)
    assert code in next(ln for ln in again.stderr.splitlines() if "Config saved to" in ln)
    for res in (key, tok, new, again):
        assert "\U0001f480" not in res.stderr and "⚠" not in res.stderr


@pytest.mark.parametrize("code", SHORTCODES)
def test_doctor_cells_keep_emoji_shortcodes_literal(code: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = tmp_path / f"H{code}x"
    (h / ".sift").mkdir(parents=True)
    _point_home(h, monkeypatch)
    monkeypatch.setattr(
        doctor_mod,
        "_check_llm_ollama",
        lambda: doctor_mod.CheckResult(name="LLM: Ollama", status=doctor_mod.CheckStatus.WARN, message="skipped"),
    )
    (h / ".sift" / ".env").write_bytes(b"SIFT_LLM_KEY=\xff\xfe\n")
    (h / ".sift" / "config.yaml").write_text("{}")
    res = CliRunner().invoke(app, ["doctor"])
    assert res.exit_code == 1, (res.output, res.exception)
    assert res.output.count(code) >= 3, res.output  # config row, credentials row, output directory row
    assert "\U0001f480" not in res.output and "⚠" not in res.output


@pytest.mark.parametrize("code", SHORTCODES)
def test_config_option_error_keeps_emoji_shortcodes_literal(code: str, home: Path, tmp_path: Path) -> None:
    res = CliRunner().invoke(app, ["validate", "x", "--config", str(tmp_path / f"m{code}.yaml")])
    assert res.exit_code == 2 and code in res.stderr


# ---------------------------------------------------------------------------
# 4. mutant pins
# ---------------------------------------------------------------------------


def test_a_non_searchable_parent_is_refused_before_any_credential(home: Path, tmp_path: Path) -> None:
    parent = tmp_path / "p"
    parent.mkdir()
    target = parent / "c.yaml"
    parent.chmod(0o600)
    try:
        with pytest.raises(config_mod.ConfigError, match="cannot write config"):
            config_mod.check_write_target(target)
        res = CliRunner().invoke(app, ["config", "--api-key", SECRET, "--provider", "mock", "--config", str(target)])
    finally:
        parent.chmod(0o700)
    assert res.exit_code == 2, (res.stderr, res.exception)
    assert not (home / ".sift" / ".env").exists()


@pytest.mark.parametrize("dir_fd", [True, False])
def test_keyboard_interrupt_during_replace_leaves_no_temp(
    dir_fd: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config_mod, "_DIR_FD_OK", dir_fd)

    def interrupt(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(config_mod.os, "replace", interrupt)
    with pytest.raises(KeyboardInterrupt):
        config_mod._write_private(tmp_path / "c.yaml", "a: 1\n")
    assert list(tmp_path.iterdir()) == []


def test_ticket_token_line_escapes_markup_on_its_own_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = tmp_path / "ho[red]me"
    (h / ".sift").mkdir(parents=True)
    _point_home(h, monkeypatch)
    res = CliRunner().invoke(app, ["config", "--ticket-provider", "thehive", "--ticket-token", "tok"])
    assert res.exit_code == 0, (res.stderr, res.exception)
    line = next(ln for ln in res.stderr.splitlines() if "Ticket token saved to" in ln)
    assert "ho[red]me" in line, line


def test_non_bmp_format_character_is_rendered_as_an_eight_digit_escape(home: Path, tmp_path: Path) -> None:
    assert config_mod._safe_path("a\U000e0041b") == "a\\U000e0041b"
    res = CliRunner().invoke(app, ["validate", "x", "--config", str(tmp_path / "t\U000e0041.yaml")])
    assert res.exit_code == 2 and "t\\U000e0041.yaml" in res.stderr
