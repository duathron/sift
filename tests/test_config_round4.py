"""Close the config/credentials error class: doctor, invisible characters, a pinned write directory.

Companion to ``test_config_error_class.py``. Everything here runs against a throwaway HOME.
"""

from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
import unicodedata
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import typer
import yaml
from typer.testing import CliRunner

import sift.config as config_mod
import sift.doctor as doctor_mod
from sift.config import ConfigError, check_write_target, load_config, read_credentials
from sift.main import app

BIDI = "‮"  # RIGHT-TO-LEFT OVERRIDE


@pytest.fixture(autouse=True)
def _wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "1000")  # Rich must not wrap a long tmp path across lines


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    (h / ".sift").mkdir(parents=True)
    _point_home(h, monkeypatch)
    return h


def _point_home(h: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setattr(config_mod, "_APP_DIR", h / ".sift")
    monkeypatch.setattr(doctor_mod, "CONFIG_PATH", h / ".sift" / "config.yaml")
    monkeypatch.setattr(doctor_mod, "OUTPUT_DIR", h / ".sift")
    monkeypatch.setattr(doctor_mod, "CACHE_DIR", h / ".sift" / "cache")
    monkeypatch.delenv("SIFT_LLM_KEY", raising=False)


@pytest.fixture
def evil_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A HOME whose name holds a bidi override, an ESC sequence and Rich markup."""
    h = tmp_path / f"ho{BIDI}me\x1b[31m[red]x"
    (h / ".sift").mkdir(parents=True)
    _point_home(h, monkeypatch)
    return h


@contextmanager
def _mode(p: Path, mode: int) -> Iterator[None]:
    old = stat.S_IMODE(os.stat(p).st_mode)
    p.chmod(mode)
    try:
        yield
    finally:
        p.chmod(old)


def _assert_clean(text: str) -> None:
    """No invisible, control or bidi character survives into the output (newline between lines aside)."""
    for ch in text:
        if ch == "\n":
            continue
        assert unicodedata.category(ch) not in config_mod._ESCAPED_CATEGORIES, (hex(ord(ch)), text)


def _run_real(args: list[str], home: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", "import sys; from sift.main import app; app()", *args],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(home), "COLUMNS": "1000"},
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# 1. sift doctor goes through the same readers as every other command
# ---------------------------------------------------------------------------


@pytest.fixture
def doctor_home(home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # no network probe from a test
    monkeypatch.setattr(
        doctor_mod,
        "_check_llm_ollama",
        lambda: doctor_mod.CheckResult(name="LLM: Ollama", status=doctor_mod.CheckStatus.WARN, message="skipped"),
    )
    return home


def _doctor(args: list[str] | None = None):
    return CliRunner().invoke(app, ["doctor", *(args or [])])


def _row(output: str, name: str) -> str:
    rows = [ln for ln in output.splitlines() if name in ln]
    assert len(rows) == 1, (name, output)
    return rows[0]


def test_doctor_non_utf8_env_is_a_fail_row_not_a_traceback(doctor_home: Path) -> None:
    (doctor_home / ".sift" / ".env").write_bytes(b"SIFT_LLM_KEY=sk-LEAKME-\xff\xfe\n")
    result = _doctor()
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.output
    row = _row(result.output, "LLM API key")
    assert "FAIL" in row and "not valid UTF-8" in row
    assert "sk-LEAKME" not in result.output and "0xff" not in result.output
    assert result.exit_code == 1  # documented: doctor exits 1 when a check fails


def test_doctor_unreadable_env_is_a_fail_row(doctor_home: Path) -> None:
    env = doctor_home / ".sift" / ".env"
    env.write_text("SIFT_LLM_KEY=sk-LEAKME\n")
    with _mode(env, 0):
        result = _doctor()
    assert "Traceback" not in result.output
    row = _row(result.output, "LLM API key")
    assert "FAIL" in row and "cannot be read" in row
    assert "sk-LEAKME" not in result.output
    assert result.exit_code == 1


def test_doctor_home_dir_mode_000_prints_the_table(doctor_home: Path) -> None:
    (doctor_home / ".sift" / "config.yaml").write_text("{}")
    with _mode(doctor_home / ".sift", 0):
        result = _doctor()
    assert "Traceback" not in result.output
    assert "sift doctor" in result.output  # the table title: the whole table was rendered
    assert "FAIL" in _row(result.output, "Config file")
    assert "cannot be read" in _row(result.output, "Config file")
    assert "FAIL" in _row(result.output, "LLM API key")
    assert "not writable" in _row(result.output, "Output directory")
    assert "WARN" in _row(result.output, "Result cache") and "permission error" in _row(result.output, "Result cache")
    assert result.exit_code == 1


def test_doctor_fifo_env_does_not_block(doctor_home: Path) -> None:
    os.mkfifo(doctor_home / ".sift" / ".env")
    proc = _run_real(["doctor"], doctor_home, timeout=60)  # a hang is a TimeoutExpired, i.e. a failure
    assert "Traceback" not in proc.stdout + proc.stderr
    row = _row(proc.stdout, "LLM API key")
    assert "FAIL" in row and "not a regular file" in row
    assert proc.returncode == 1


def test_doctor_fifo_config_does_not_block(doctor_home: Path) -> None:
    os.mkfifo(doctor_home / ".sift" / "config.yaml")
    proc = _run_real(["doctor"], doctor_home, timeout=60)
    assert "Traceback" not in proc.stdout + proc.stderr
    row = _row(proc.stdout, "Config file")
    assert "FAIL" in row and "not a regular file" in row
    assert proc.returncode == 1


def test_doctor_healthy_home_unchanged(doctor_home: Path) -> None:
    (doctor_home / ".sift" / "config.yaml").write_text("{}")
    (doctor_home / ".sift" / ".env").write_text("SIFT_LLM_KEY=abcd1234\n")
    (doctor_home / ".sift" / "cache").mkdir()
    result = _doctor()
    assert "PASS" in _row(result.output, "Config file")
    key_row = _row(result.output, "LLM API key")
    assert "PASS" in key_row and "****1234" in key_row and "abcd1234" not in key_row and ".env" in key_row
    assert "PASS" in _row(result.output, "Output directory")
    assert "ready" in _row(result.output, "Result cache")


def test_doctor_env_var_wins_without_reading_the_file(doctor_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (doctor_home / ".sift" / ".env").write_bytes(b"\xff\xfe")
    monkeypatch.setenv("SIFT_LLM_KEY", "envkey-9876")
    row = _row(_doctor().output, "LLM API key")
    assert "PASS" in row and "****9876" in row and "env var" in row


def test_doctor_missing_config_and_dir_are_not_a_crash(doctor_home: Path) -> None:
    result = _doctor()
    assert "WARN" in _row(result.output, "Config file") and "defaults" in _row(result.output, "Config file")
    assert "not initialized" in _row(result.output, "Result cache")


def test_doctor_output_directory_missing_is_a_fail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_mod, "OUTPUT_DIR", tmp_path / "nowhere")
    res = doctor_mod._check_output_directory()
    assert res.status is doctor_mod.CheckStatus.FAIL and "does not exist" in res.message


def test_doctor_unexaminable_output_directory_is_not_reported_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outer = tmp_path / f"out{BIDI}er"
    (outer / ".sift").mkdir(parents=True)
    monkeypatch.setattr(doctor_mod, "OUTPUT_DIR", outer / ".sift")
    monkeypatch.setattr(doctor_mod, "CACHE_DIR", outer / ".sift" / "cache")
    with _mode(outer, 0):
        out = doctor_mod._check_output_directory()
        cache = doctor_mod._check_cache_directory()
    assert out.status is doctor_mod.CheckStatus.FAIL and "not writable" in out.message
    assert cache.status is doctor_mod.CheckStatus.WARN and "permission error" in cache.message
    assert "\\u202e" in cache.message
    _assert_clean(cache.message + out.message)


def test_doctor_paths_are_escaped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / f"a{BIDI}exe.yaml"
    cfg.write_text("{}")
    monkeypatch.setattr(doctor_mod, "CONFIG_PATH", cfg)
    ok = doctor_mod._check_config_file()
    assert ok.status is doctor_mod.CheckStatus.PASS and "\\u202e" in ok.message
    _assert_clean(ok.message)
    fifo = tmp_path / f"b{BIDI}pipe.yaml"
    os.mkfifo(fifo)
    monkeypatch.setattr(doctor_mod, "CONFIG_PATH", fifo)
    bad = doctor_mod._check_config_file()
    assert bad.status is doctor_mod.CheckStatus.FAIL and "\\u202e" in bad.message
    _assert_clean(bad.message)
    monkeypatch.setattr(doctor_mod, "OUTPUT_DIR", tmp_path / f"c{BIDI}d")
    monkeypatch.setattr(doctor_mod, "CACHE_DIR", tmp_path / f"c{BIDI}d" / "cache")
    out = doctor_mod._check_output_directory()
    _assert_clean(out.message)
    assert "\\u202e" in out.message


def test_doctor_reads_credentials_through_the_one_reader(doctor_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Path] = []

    def fake(env_file: Path) -> dict:
        seen.append(env_file)
        return {"SIFT_LLM_KEY": "zzzz4321"}

    monkeypatch.setattr(doctor_mod, "read_credentials", fake)
    assert "****4321" in doctor_mod._check_llm_key().message
    assert seen == [doctor_home / ".sift" / ".env"]


# ---------------------------------------------------------------------------
# 2. _safe_path escapes by Unicode category, not from a list
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("char", "escaped"),
    [
        ("‪", "\\u202a"),
        ("‮", "\\u202e"),
        ("⁦", "\\u2066"),
        ("⁩", "\\u2069"),
        ("​", "\\u200b"),
        ("‍", "\\u200d"),
        ("‏", "\\u200f"),
        ("؜", "\\u061c"),
        ("﻿", "\\ufeff"),
        ("­", "\\xad"),
        ("⁠", "\\u2060"),
        ("\U000e0041", "\\U000e0041"),  # tag character
        ("\x00", "\\x00"),
        ("\x1b", "\\x1b"),
        ("\x7f", "\\x7f"),
        ("\x9b", "\\x9b"),
        (" ", "\\u2028"),
        (" ", "\\u2029"),
        ("\ud800", "\\ud800"),
    ],
)
def test_safe_path_escapes_every_invisible_category(char: str, escaped: str) -> None:
    assert config_mod._safe_path(Path(f"a{char}b")) == f"a{escaped}b"


@pytest.mark.parametrize(
    "text", ["plain/ü.yaml", "日本語/設定.yaml", "emoji-\U0001f600.yaml", "sp ace/tab\t.yaml".replace("\t", "_")]
)
def test_safe_path_keeps_printable_text(text: str) -> None:
    assert config_mod._safe_path(Path(text)) == text


@pytest.mark.parametrize("char", ["‮", "⁦", "​", "\U000e0041"])
@pytest.mark.parametrize("command", ["triage", "validate", "metrics", "config"])
def test_invisible_characters_never_reach_a_message(command: str, char: str, home: Path, tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.json"
    alerts.write_text("[]")
    cfg = tmp_path / f"a{char}exe.yaml"
    argv = (
        ["config", "--show", "--config", str(cfg)]
        if command == "config"
        else [command, str(alerts), "--config", str(cfg)]
    )
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == 2, (result.stderr, result.exception)
    _assert_clean(result.stderr)
    assert "not found" in result.stderr


# every sink that prints a path: stat / load / write errors, saved, created, API key, ticket token
def test_stat_cannot_be_read_message_is_escaped(home: Path, tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path / (f"x{BIDI}" + "a" * 300))
    assert "cannot be read" in str(ei.value) and "\\u202e" in str(ei.value)
    _assert_clean(str(ei.value))


def test_not_a_regular_file_message_is_escaped(home: Path, tmp_path: Path) -> None:
    fifo = tmp_path / f"p{BIDI}ipe.yaml"
    os.mkfifo(fifo)
    with pytest.raises(ConfigError) as ei:
        load_config(fifo)
    assert "not a regular file" in str(ei.value) and "\\u202e" in str(ei.value)
    _assert_clean(str(ei.value))


def test_cannot_write_config_message_is_escaped_in_the_precheck(home: Path, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app, ["config", "--provider", "mock", "--config", str(tmp_path / f"no{BIDI}dir" / "x.yaml")]
    )
    assert result.exit_code == 2
    assert "cannot write config" in result.stderr and "\\u202e" in result.stderr
    _assert_clean(result.stderr)


def test_cannot_write_config_message_is_escaped_after_the_precheck(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(config_mod, "save_config", boom)
    result = CliRunner().invoke(app, ["config", "--provider", "mock", "--config", str(tmp_path / f"o{BIDI}k.yaml")])
    assert result.exit_code == 2
    assert "cannot write config" in result.stderr and "\\u202e" in result.stderr
    _assert_clean(result.stderr)


def test_cannot_write_credentials_message_is_escaped(evil_home: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim.env"
    victim.write_text("")
    (evil_home / ".sift" / ".env").symlink_to(victim)
    result = CliRunner().invoke(app, ["config", "--api-key", "sk-FAKE"])
    assert result.exit_code == 2
    assert "cannot write credentials file" in result.stderr and "\\u202e" in result.stderr
    assert "\x1b" not in result.stderr
    _assert_clean(result.stderr)
    assert victim.read_text() == ""


def test_created_and_saved_paths_are_escaped_for_terminal_and_rich(home: Path, tmp_path: Path) -> None:
    target = tmp_path / f"n{BIDI}ew[red]x.yaml"
    first = CliRunner().invoke(app, ["config", "--provider", "mock", "--config", str(target)])
    assert first.exit_code == 0, (first.stderr, first.exception)
    assert "created new config" in first.stderr and "\\u202e" in first.stderr and "[red]" in first.stderr
    _assert_clean(first.stderr)
    second = CliRunner().invoke(app, ["config", "--provider", "template", "--config", str(target)])
    assert "Config saved to" in second.stderr and "\\u202e" in second.stderr and "[red]" in second.stderr
    _assert_clean(second.stderr)


def test_api_key_and_ticket_token_saved_paths_are_escaped(evil_home: Path) -> None:
    key = CliRunner().invoke(app, ["config", "--api-key", "sk-FAKE"])
    assert key.exit_code == 0, (key.stderr, key.exception)
    assert "API key saved to" in key.stderr and "\\u202e" in key.stderr
    assert "[red]" in key.stderr and "\x1b" not in key.stderr  # markup is shown, not interpreted
    _assert_clean(key.stderr)
    tok = CliRunner().invoke(app, ["config", "--ticket-provider", "thehive", "--ticket-token", "tok-FAKE"])
    assert tok.exit_code == 0, (tok.stderr, tok.exception)
    assert "Ticket token saved to" in tok.stderr and "\\u202e" in tok.stderr and "[red]" in tok.stderr
    _assert_clean(tok.stderr)


# ---------------------------------------------------------------------------
# 3. the write directory is resolved once and pinned
# ---------------------------------------------------------------------------


def _swap_parent(real: Path, victim: Path, moved: Path):
    def swap() -> None:
        real.rename(moved)
        real.symlink_to(victim, target_is_directory=True)

    return swap


def test_parent_swapped_after_the_check_does_not_redirect_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real, victim, moved = tmp_path / "real", tmp_path / "victim", tmp_path / "moved"
    real.mkdir()
    victim.mkdir()
    (victim / "c.yaml").write_text("VICTIM")
    monkeypatch.setattr(config_mod, "_after_parent_pinned", _swap_parent(real, victim, moved))
    config_mod._write_private(real / "c.yaml", "data: 1\n")
    assert (victim / "c.yaml").read_text() == "VICTIM"
    assert sorted(p.name for p in victim.iterdir()) == ["c.yaml"]
    assert (moved / "c.yaml").read_text() == "data: 1\n"  # it landed in the directory that was pinned
    assert sorted(p.name for p in moved.iterdir()) == ["c.yaml"]  # no temp file left behind


def test_leaf_is_judged_in_the_pinned_directory_not_the_swapped_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real, victim, moved = tmp_path / "real", tmp_path / "victim", tmp_path / "moved"
    real.mkdir()
    victim.mkdir()
    (victim / "c.yaml").symlink_to(tmp_path / "elsewhere")  # would be refused if looked up through the swapped path
    monkeypatch.setattr(config_mod, "_after_parent_pinned", _swap_parent(real, victim, moved))
    config_mod._write_private(real / "c.yaml", "data: 1\n")
    assert (moved / "c.yaml").read_text() == "data: 1\n"
    assert os.path.islink(victim / "c.yaml")


def test_directory_descriptor_is_closed(tmp_path: Path) -> None:
    def open_fds() -> int:
        return len(os.listdir("/dev/fd"))

    config_mod._write_private(tmp_path / "warm.yaml", "a: 1\n")
    before = open_fds()
    for i in range(5):
        config_mod._write_private(tmp_path / "c.yaml", f"a: {i}\n")
    with pytest.raises(OSError):
        config_mod._write_private(tmp_path / "nodir" / "c.yaml", "a: 1\n")
    assert open_fds() == before


def test_failed_write_after_a_parent_swap_leaves_no_orphan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real, victim, moved = tmp_path / "real", tmp_path / "victim", tmp_path / "moved"
    real.mkdir()
    victim.mkdir()
    monkeypatch.setattr(config_mod, "_after_parent_pinned", _swap_parent(real, victim, moved))

    def boom(*_a, **_k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(config_mod.os, "replace", boom)
    with pytest.raises(OSError):
        config_mod._write_private(real / "c.yaml", "data: 1\n")
    assert list(victim.iterdir()) == []
    assert list(moved.iterdir()) == []  # the temp file was removed through the pinned descriptor


def test_leaf_symlink_swapped_in_after_pinning_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("VICTIM")
    target = tmp_path / "c.yaml"
    monkeypatch.setattr(config_mod, "_after_parent_pinned", lambda: target.symlink_to(victim))
    with pytest.raises(OSError):
        config_mod._write_private(target, "data: 1\n")
    assert victim.read_text() == "VICTIM"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["c.yaml", "victim.txt"]


def test_leaf_fifo_is_refused_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "c.yaml"
    os.mkfifo(target)
    with pytest.raises(OSError):
        config_mod._write_private(target, "data: 1\n")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["c.yaml"]


def test_symlinked_parent_is_followed_once_like_a_managed_dotfile_dir(tmp_path: Path) -> None:
    real = tmp_path / "dotfiles" / "sift"
    real.mkdir(parents=True)
    link = tmp_path / ".sift"
    link.symlink_to(real, target_is_directory=True)
    config_mod._write_private(link / "config.yaml", "a: 1\n")
    assert (real / "config.yaml").read_text() == "a: 1\n"
    assert stat.S_IMODE(os.stat(real / "config.yaml").st_mode) == 0o600
    assert not any(p.name.endswith(".tmp") for p in real.iterdir())


def test_write_replaces_a_loose_file_with_a_private_one(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.write_text("old")
    target.chmod(0o666)
    old_umask = os.umask(0)
    try:
        config_mod._write_private(target, "new\n")
    finally:
        os.umask(old_umask)
    assert target.read_text() == "new\n"
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == [".env"]


def test_parent_that_became_a_symlink_before_the_open_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # realpath returned a real directory, then it was swapped for a symlink before os.open
    real, victim = tmp_path / "real", tmp_path / "victim"
    real.mkdir()
    victim.mkdir()
    swapped = tmp_path / "swapped"
    swapped.symlink_to(victim, target_is_directory=True)
    monkeypatch.setattr(config_mod.os.path, "realpath", lambda _p: str(swapped))
    with pytest.raises(OSError):
        config_mod._write_private(real / "c.yaml", "data: 1\n")
    assert list(victim.iterdir()) == [] and list(real.iterdir()) == []


def test_existing_temp_name_is_never_overwritten_or_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.secrets, "token_hex", lambda _n: "fixed")
    foreign = tmp_path / ".c.yaml.fixed.tmp"
    foreign.write_text("FOREIGN")
    with pytest.raises(FileExistsError):
        config_mod._write_private(tmp_path / "c.yaml", "data: 1\n")
    assert foreign.read_text() == "FOREIGN"
    assert not (tmp_path / "c.yaml").exists()


def test_restrictive_umask_still_gives_a_0600_file(tmp_path: Path) -> None:
    old = os.umask(0o277)
    try:
        config_mod._write_private(tmp_path / "c.yaml", "a: 1\n")
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(tmp_path / "c.yaml").st_mode) == 0o600


def test_data_is_synced_before_the_rename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(config_mod.os, "fsync", lambda fd: (order.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(config_mod.os, "replace", lambda *a, **k: (order.append("replace"), real_replace(*a, **k))[1])
    config_mod._write_private(tmp_path / "c.yaml", "a: 1\n")
    assert order == ["fsync", "replace"]


def test_cleanup_failure_does_not_mask_the_original_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def full(*_a, **_k):
        raise OSError(errno.ENOSPC, "full")

    def stuck(*_a, **_k):
        raise PermissionError(errno.EPERM, "cannot unlink")

    monkeypatch.setattr(config_mod.os, "replace", full)
    monkeypatch.setattr(config_mod.os, "unlink", stuck)
    with pytest.raises(OSError) as ei:
        config_mod._write_private(tmp_path / "c.yaml", "a: 1\n")
    assert ei.value.errno == errno.ENOSPC


def test_missing_parent_is_an_oserror(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        config_mod._write_private(tmp_path / "nodir" / "c.yaml", "x")


def test_dir_fd_is_available_on_this_platform() -> None:
    assert config_mod._DIR_FD_OK is config_mod._dir_fd_supported() is (os.name == "posix")


def test_fallback_without_dir_fd_still_refuses_a_leaf_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod, "_DIR_FD_OK", False)
    ok = tmp_path / "ok.yaml"
    config_mod._write_private(ok, "a: 1\n")
    assert ok.read_text() == "a: 1\n" and stat.S_IMODE(os.stat(ok).st_mode) == 0o600
    victim = tmp_path / "victim.txt"
    victim.write_text("VICTIM")
    link = tmp_path / "link.yaml"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        config_mod._write_private(link, "a: 1\n")
    assert victim.read_text() == "VICTIM"
    assert not any(p.name.endswith(".tmp") for p in tmp_path.iterdir())


def test_fallback_cleans_its_temp_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod, "_DIR_FD_OK", False)

    def boom(*_a, **_k):
        raise OSError(errno.ENOSPC, "full")

    monkeypatch.setattr(config_mod.os, "replace", boom)
    with pytest.raises(OSError):
        config_mod._write_private(tmp_path / "c.yaml", "a: 1\n")
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# 4. order: the default directory is healed before the config target is judged
# ---------------------------------------------------------------------------


def test_home_dir_mode_0500_is_healed_for_a_plain_config_write(home: Path) -> None:
    sift_dir = home / ".sift"
    sift_dir.chmod(0o500)
    try:
        result = CliRunner().invoke(app, ["config", "--provider", "template"])
        assert result.exit_code == 0, (result.stderr, result.exception)
        assert stat.S_IMODE(os.stat(sift_dir).st_mode) == 0o700
        assert yaml.safe_load((sift_dir / "config.yaml").read_text())["summarize"]["provider"] == "template"
    finally:
        sift_dir.chmod(0o700)


def test_api_key_and_config_behave_alike_on_a_0500_home_dir(home: Path) -> None:
    sift_dir = home / ".sift"
    sift_dir.chmod(0o500)
    try:
        result = CliRunner().invoke(app, ["config", "--api-key", "sk-FAKE", "--provider", "mock"])
        assert result.exit_code == 0, (result.stderr, result.exception)
    finally:
        sift_dir.chmod(0o700)
    assert "SIFT_LLM_KEY=sk-FAKE" in (sift_dir / ".env").read_text()


def test_first_run_without_a_home_dir_creates_it_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = tmp_path / "fresh"
    h.mkdir()
    _point_home(h, monkeypatch)
    result = CliRunner().invoke(app, ["config", "--provider", "mock"])
    assert result.exit_code == 0, (result.stderr, result.exception)
    assert "created new config" in result.stderr
    assert stat.S_IMODE(os.stat(h / ".sift").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(h / ".sift" / "config.yaml").st_mode) == 0o600


def test_home_path_that_is_a_file_is_one_line_exit_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = tmp_path / "h"
    h.mkdir()
    (h / ".sift").write_text("i am a file")
    _point_home(h, monkeypatch)
    result = CliRunner().invoke(app, ["config", "--api-key", "sk-FAKE", "--provider", "mock"])
    assert result.exit_code == 2, (result.stderr, result.exception)
    assert "Traceback" not in result.stderr and result.stderr.startswith("sift: cannot write")
    assert len([ln for ln in result.stderr.splitlines() if ln.strip()]) == 1


# ---------------------------------------------------------------------------
# 5. every setting flag: one table drives "will save" and the assignment
# ---------------------------------------------------------------------------

# flag param name -> (argv, key path in the saved YAML, expected value)
SETTING_FLAGS: dict[str, tuple[list[str], tuple[str, ...], object]] = {
    "provider": (["--provider", "mock"], ("summarize", "provider"), "mock"),
    "model": (["--model", "m-1"], ("summarize", "model"), "m-1"),
    "quiet": (["--quiet"], ("output", "quiet"), True),
    "default_format": (["--default-format", "json"], ("output", "default_format"), "json"),
    "chunk_size": (["--chunk-size", "7"], ("clustering", "chunk_size"), 7),
    "cache": (["--no-cache"], ("cache_enabled",), False),
    "enrich_consent": (["--enrich-consent"], ("enrich", "consent_given"), True),
    "redact_fields_default": (["--redact-fields", "user,host"], ("redaction", "fields"), ["user", "host"]),
    "ticket_provider": (["--ticket-provider", "jira"], ("ticketing", "provider"), "jira"),
    "ticket_url": (["--ticket-url", "https://t.example"], ("ticketing", "url"), "https://t.example"),
    "ticket_project": (["--ticket-project", "SOC"], ("ticketing", "project_key"), "SOC"),
    "ticket_jira_email": (["--ticket-jira-email", "a@b.example"], ("ticketing", "jira_email"), "a@b.example"),
}
# flags that are not config settings: they never make a run save config.yaml
NOT_SETTINGS = {"show", "api_key", "unset_api_key", "ticket_token", "config_path", "help"}


FALSY_VALUES = [
    (["--no-quiet"], ("output", "quiet"), False),
    (["--chunk-size", "0"], ("clustering", "chunk_size"), 0),
    (["--redact-fields", ""], ("redaction", "fields"), []),
    (["--no-enrich-consent"], ("enrich", "consent_given"), False),
    (["--model", ""], ("summarize", "model"), ""),
    (["--ticket-url", ""], ("ticketing", "url"), ""),
]


@pytest.mark.parametrize(("argv", "path", "value"), FALSY_VALUES)
def test_falsy_values_still_count_as_a_change(
    argv: list[str], path: tuple[str, ...], value: object, home: Path, tmp_path: Path
) -> None:
    target = tmp_path / "out.yaml"
    result = CliRunner().invoke(app, ["config", *argv, "--config", str(target)])
    assert result.exit_code == 0, (result.stderr, result.exception)
    saved: object = yaml.safe_load(target.read_text())
    for key in path:
        saved = saved[key]  # type: ignore[index]
    assert saved == value
    bad = tmp_path / "nodir" / "x.yaml"
    refused = CliRunner().invoke(app, ["config", "--api-key", "sk-FAKE", *argv, "--config", str(bad)])
    assert refused.exit_code == 2 and not (home / ".sift" / ".env").exists()


def test_every_config_flag_is_classified() -> None:
    command = typer.main.get_command(app).commands["config"]
    names = {p.name for p in command.params}
    assert names - NOT_SETTINGS == set(SETTING_FLAGS), "a new `sift config` flag needs an entry in SETTING_FLAGS"
    # every listed argv really names the parameter it claims
    for name, (argv, _path, _value) in SETTING_FLAGS.items():
        param = next(p for p in command.params if p.name == name)
        assert argv[0] in param.opts + param.secondary_opts, name


@pytest.mark.parametrize("name", sorted(SETTING_FLAGS))
def test_every_setting_flag_saves_its_value(name: str, home: Path, tmp_path: Path) -> None:
    argv, path, value = SETTING_FLAGS[name]
    target = tmp_path / "out.yaml"
    result = CliRunner().invoke(app, ["config", *argv, "--config", str(target)])
    assert result.exit_code == 0, (result.stderr, result.exception)
    saved: object = yaml.safe_load(target.read_text())
    for key in path:
        saved = saved[key]  # type: ignore[index]
    assert saved == value


@pytest.mark.parametrize("name", sorted(SETTING_FLAGS))
def test_no_credential_is_written_when_the_config_target_is_bad(name: str, home: Path, tmp_path: Path) -> None:
    argv, _path, _value = SETTING_FLAGS[name]
    bad = tmp_path / "nodir" / "x.yaml"
    result = CliRunner().invoke(app, ["config", "--api-key", "sk-FAKE-KEY", *argv, "--config", str(bad)])
    assert result.exit_code == 2, (result.stderr, result.exception)
    assert not (home / ".sift" / ".env").exists()
    assert "sk-FAKE-KEY" not in result.stderr + result.stdout
    assert not bad.parent.exists()


@pytest.mark.parametrize("name", sorted(SETTING_FLAGS))
def test_no_ticket_token_is_written_when_the_config_target_is_bad(name: str, home: Path, tmp_path: Path) -> None:
    argv, _path, _value = SETTING_FLAGS[name]
    bad = tmp_path / "nodir" / "x.yaml"
    result = CliRunner().invoke(
        app, ["config", "--ticket-provider", "thehive", "--ticket-token", "tok-FAKE", *argv, "--config", str(bad)]
    )
    assert result.exit_code == 2, (result.stderr, result.exception)
    assert not (home / ".sift" / ".env").exists()


def test_a_run_without_setting_flags_does_not_refuse_a_bad_target(home: Path, tmp_path: Path) -> None:
    # --api-key alone writes only the credentials file; the config target is never touched
    result = CliRunner().invoke(app, ["config", "--api-key", "sk-FAKE", "--config", str(tmp_path / "nodir" / "x.yaml")])
    assert result.exit_code == 0, (result.stderr, result.exception)
    assert "SIFT_LLM_KEY=sk-FAKE" in (home / ".sift" / ".env").read_text()


# ---------------------------------------------------------------------------
# 6. pins for the pre-write refusal and its helpers
# ---------------------------------------------------------------------------


def test_read_only_parent_is_refused_before_any_credential(home: Path, tmp_path: Path) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    with _mode(ro, 0o500):
        result = CliRunner().invoke(
            app, ["config", "--api-key", "sk-FAKE", "--provider", "mock", "--config", str(ro / "c.yaml")]
        )
    assert result.exit_code == 2, (result.stderr, result.exception)
    assert "cannot write config" in result.stderr
    assert not (home / ".sift" / ".env").exists()


def test_parent_that_is_an_executable_file_is_refused(home: Path, tmp_path: Path) -> None:
    parent = tmp_path / "afile"
    parent.write_text("x")
    parent.chmod(0o700)  # writable and executable: os.access alone would accept it; lstat (ENOTDIR) refuses
    with pytest.raises(ConfigError):
        check_write_target(parent / "c.yaml")
    result = CliRunner().invoke(
        app, ["config", "--api-key", "sk-FAKE", "--provider", "mock", "--config", str(parent / "c.yaml")]
    )
    assert result.exit_code == 2
    assert not (home / ".sift" / ".env").exists()


def test_lstat_failure_is_cannot_write_not_a_traceback(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot write config") as ei:
        check_write_target(tmp_path / ("a" * 300 + ".yaml"))  # ENAMETOOLONG from lstat
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


def test_check_write_target_reports_new_versus_existing(tmp_path: Path) -> None:
    existing = tmp_path / "there.yaml"
    existing.write_text("{}")
    assert check_write_target(tmp_path / "new.yaml") is True
    assert check_write_target(existing) is False


@pytest.mark.parametrize("kind", ["symlink_to_file", "dangling", "directory", "fifo"])
def test_check_write_target_refuses_every_non_regular_leaf(kind: str, tmp_path: Path) -> None:
    target = tmp_path / "t.yaml"
    if kind == "symlink_to_file":
        (tmp_path / "real.yaml").write_text("{}")
        target.symlink_to(tmp_path / "real.yaml")
    elif kind == "dangling":
        target.symlink_to(tmp_path / "nowhere")
    elif kind == "directory":
        target.mkdir()
    else:
        os.mkfifo(target)
    with pytest.raises(ConfigError, match="cannot write config"):
        check_write_target(target)


def test_oserror_from_ensure_dir_in_the_precheck_is_exit_2(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> Path:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr("sift.main._ensure_config_dir", boom)
    result = CliRunner().invoke(app, ["config", "--provider", "mock"])
    assert result.exit_code == 2 and "cannot write config" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("kind", ["symlink_loop", "parent_is_file"])
def test_loop_and_not_a_directory_read_as_not_found(kind: str, home: Path, tmp_path: Path) -> None:
    if kind == "symlink_loop":
        target = tmp_path / "loop.yaml"
        target.symlink_to(target)
    else:
        (tmp_path / "afile").write_text("x")
        target = tmp_path / "afile" / "c.yaml"
    with pytest.raises(ConfigError, match="--config file not found"):
        load_config(target)


def test_missing_errnos_are_exactly_the_not_there_cases() -> None:
    assert set(config_mod._MISSING_ERRNOS) == {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}


def test_load_yaml_refuses_a_fifo_by_itself(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.yaml"
    os.mkfifo(fifo)
    with pytest.raises(ConfigError, match="not a regular file"):
        config_mod._load_yaml(fifo)  # called directly: no earlier stat protects it


def test_legacy_notice_quotes_no_source_line() -> None:
    config_mod._LEGACY_REDACT_RAW_WARNED = False
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            config_mod.AlertRedactionConfig.model_validate({"redact_raw": True})
    finally:
        config_mod._LEGACY_REDACT_RAW_WARNED = True
    assert len(caught) == 1
    assert caught[0].lineno == 0 and caught[0].filename == config_mod.__file__
    assert issubclass(caught[0].category, FutureWarning)


# ---------------------------------------------------------------------------
# 7. credentials file: one reader, one writer, never through a symlink
# ---------------------------------------------------------------------------


def test_read_credentials_cases(tmp_path: Path) -> None:
    assert read_credentials(tmp_path / "absent.env") == {}
    env = tmp_path / ".env"
    env.write_text("A=1\nB=two\n")
    assert read_credentials(env) == {"A": "1", "B": "two"}
    env.write_bytes(b"A=\xff\n")
    with pytest.raises(ConfigError, match="not valid UTF-8") as ei:
        read_credentials(env)
    assert ei.value.__cause__ is None and "\\xff" not in str(ei.value)
    os.mkfifo(tmp_path / "pipe.env")
    with pytest.raises(ConfigError, match="not a regular file"):
        read_credentials(tmp_path / "pipe.env")


def test_credentials_error_path_is_escaped(evil_home: Path) -> None:
    (evil_home / ".sift" / ".env").write_bytes(b"SIFT_LLM_KEY=\xff\n")
    with pytest.raises(ConfigError) as ei:
        read_credentials(evil_home / ".sift" / ".env")
    assert "\\u202e" in str(ei.value)
    _assert_clean(str(ei.value))
    os.chmod(evil_home / ".sift" / ".env", 0)
    try:
        with pytest.raises(ConfigError) as ei2:
            read_credentials(evil_home / ".sift" / ".env")
    finally:
        os.chmod(evil_home / ".sift" / ".env", 0o600)
    assert "\\u202e" in str(ei2.value)
    _assert_clean(str(ei2.value))


def test_environment_wins_over_the_credentials_file(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (home / ".sift" / ".env").write_text("SIFT_LLM_KEY=from-file\nSIFT_OTHER=from-file\n")
    monkeypatch.setenv("SIFT_LLM_KEY", "from-env")
    monkeypatch.delenv("SIFT_OTHER", raising=False)
    try:
        cfg = load_config()
        assert cfg.summarize.api_key == "from-env"
        assert os.environ["SIFT_OTHER"] == "from-file"
    finally:
        os.environ.pop("SIFT_OTHER", None)


def test_symlinked_env_is_not_even_read_by_the_writers(home: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim.env"
    victim.write_text("SIFT_LLM_KEY=VICTIMSECRET\n")
    (home / ".sift" / ".env").symlink_to(victim)
    with pytest.raises(OSError):
        config_mod.save_credentials("k")
    with pytest.raises(OSError):
        config_mod.save_ticket_token("t", "jira")
    with pytest.raises(OSError):
        config_mod.clear_credentials()
    assert victim.read_text() == "SIFT_LLM_KEY=VICTIMSECRET\n"


def test_symlinked_env_target_is_never_opened_for_reading(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "victim.env"
    victim.write_text("SIFT_LLM_KEY=VICTIMSECRET\n")
    (home / ".sift" / ".env").symlink_to(victim)

    def no_read(_self, *_a, **_k):
        raise AssertionError("the symlink target was read")

    monkeypatch.setattr(Path, "read_text", no_read)
    for call in (
        lambda: config_mod.save_credentials("k"),
        lambda: config_mod.save_ticket_token("t", "jira"),
        lambda: config_mod.clear_credentials(),
    ):
        with pytest.raises(OSError):
            call()


def test_bare_key_in_env_file_is_ignored_not_a_crash(home: Path) -> None:
    (home / ".sift" / ".env").write_text("BARE_KEY_NO_VALUE\nSIFT_LLM_KEY=real\n")
    assert read_credentials(home / ".sift" / ".env") == {"BARE_KEY_NO_VALUE": None, "SIFT_LLM_KEY": "real"}
    assert load_config().summarize.api_key == "real"
    assert "BARE_KEY_NO_VALUE" not in os.environ


def test_custom_config_path_does_not_create_the_home_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = tmp_path / "fresh"
    h.mkdir()
    _point_home(h, monkeypatch)
    result = CliRunner().invoke(app, ["config", "--provider", "mock", "--config", str(tmp_path / "mine.yaml")])
    assert result.exit_code == 0, (result.stderr, result.exception)
    assert not (h / ".sift").exists()


def test_ticket_token_into_a_symlinked_env_is_exit_2(home: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim.env"
    victim.write_text("")
    (home / ".sift" / ".env").symlink_to(victim)
    result = CliRunner().invoke(app, ["config", "--ticket-provider", "thehive", "--ticket-token", "tok-FAKE"])
    assert result.exit_code == 2, (result.stderr, result.exception)
    assert "cannot write credentials file" in result.stderr and "Traceback" not in result.stderr
    assert "tok-FAKE" not in result.stderr
    assert victim.read_text() == ""


def test_unset_api_key_on_a_symlinked_env_is_exit_2(home: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim.env"
    victim.write_text("SIFT_LLM_KEY=VICTIMSECRET\n")
    (home / ".sift" / ".env").symlink_to(victim)
    result = CliRunner().invoke(app, ["config", "--unset-api-key"])
    assert result.exit_code == 2, (result.stderr, result.exception)
    assert "cannot write credentials file" in result.stderr and "Traceback" not in result.stderr
    assert "VICTIMSECRET" not in result.stderr + result.stdout
    assert victim.read_text() == "SIFT_LLM_KEY=VICTIMSECRET\n"


def test_credentials_round_trip(home: Path) -> None:
    config_mod.save_credentials("k1")
    config_mod.save_ticket_token("t1", "thehive")
    config_mod.save_ticket_token("t2", "jira")
    config_mod.save_credentials("k2")
    text = (home / ".sift" / ".env").read_text()
    assert text.count("SIFT_LLM_KEY=") == 1 and "SIFT_LLM_KEY=k2" in text
    assert "SIFT_THEHIVE_TOKEN=t1" in text and "SIFT_JIRA_TOKEN=t2" in text
    assert config_mod.clear_credentials() is True
    assert config_mod.clear_credentials() is False
    assert "SIFT_LLM_KEY" not in (home / ".sift" / ".env").read_text()


def test_clear_credentials_without_a_file_is_false(home: Path) -> None:
    assert config_mod.clear_credentials() is False
