"""Every config/credentials problem reachable from the CLI is one value-free `sift: ...` line, exit 2."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import sift.config as config_mod
from sift.config import ConfigError, load_config
from sift.main import app

COMMANDS = ["triage", "validate", "metrics", "config"]


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    (h / ".sift").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setattr(config_mod, "_APP_DIR", h / ".sift")
    monkeypatch.delenv("SIFT_LLM_KEY", raising=False)
    return h


@pytest.fixture
def alerts(tmp_path: Path) -> Path:
    f = tmp_path / "alerts.json"
    f.write_text("[]")
    return f


def _argv(command: str, alerts: Path, cfg: Path | str) -> list[str]:
    if command == "config":
        return ["config", "--show", "--config", str(cfg)]
    return [command, str(alerts), "--config", str(cfg)]


@contextmanager
def _mode000(p: Path) -> Iterator[None]:
    old = stat.S_IMODE(os.stat(p).st_mode)
    p.chmod(0)
    try:
        yield
    finally:
        p.chmod(old)


def _one_line(result) -> str:
    out = result.stderr
    assert "Traceback" not in out + result.stdout
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(lines) == 1, out
    assert lines[0].startswith("sift: "), out
    for ch in out:
        assert ch in "\n" or ord(ch) >= 0x20, repr(out)
    return lines[0]


def _run_real(args: list[str], home: Path, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", "import sys; from sift.main import app; app()", *args],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
        timeout=timeout,
    )


# --- 1. ~/.sift/.env load errors ---------------------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_env_file_not_utf8_is_one_line_exit_2(command: str, home: Path, tmp_path: Path, alerts: Path) -> None:
    (home / ".sift" / ".env").write_bytes(b"SIFT_LLM_KEY=sk-LEAKME-\xff\xfe\n")
    ok = tmp_path / "ok.yaml"
    ok.write_text("{}")
    result = CliRunner().invoke(app, _argv(command, alerts, ok))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    line = _one_line(result)
    assert "credentials file" in line and "UTF-8" in line
    assert "sk-LEAKME" not in result.stderr + result.stdout and "0xff" not in result.stderr


def test_env_file_unreadable_is_one_line_exit_2(home: Path, tmp_path: Path, alerts: Path) -> None:
    env = home / ".sift" / ".env"
    env.write_text("SIFT_LLM_KEY=sk-LEAKME\n")
    ok = tmp_path / "ok.yaml"
    ok.write_text("{}")
    with _mode000(env):
        result = CliRunner().invoke(app, _argv("validate", alerts, ok))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    assert "credentials file" in _one_line(result) and "cannot be read" in result.stderr


def test_env_file_error_has_no_chained_cause(home: Path) -> None:
    (home / ".sift" / ".env").write_bytes(b"\xff\xfe\n")
    with pytest.raises(ConfigError) as ei:
        load_config()
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


# --- 2. stat failures on an explicit --config ---------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_config_parent_dir_unreadable_is_exit_2(command: str, home: Path, tmp_path: Path, alerts: Path) -> None:
    d = tmp_path / "denied"
    d.mkdir()
    (d / "c.yaml").write_text("{}")
    with _mode000(d):
        result = CliRunner().invoke(app, _argv(command, alerts, d / "c.yaml"))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    # Python 3.13 swallows the stat error in Path.exists(); the message must still not claim "not found"
    assert "cannot be read" in _one_line(result) and "not found" not in result.stderr


@pytest.mark.parametrize("command", COMMANDS)
def test_config_name_too_long_is_exit_2(command: str, home: Path, tmp_path: Path, alerts: Path) -> None:
    result = CliRunner().invoke(app, _argv(command, alerts, tmp_path / ("a" * 300 + ".yaml")))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    assert "cannot be read" in _one_line(result) and "not found" not in result.stderr


def test_stat_failure_has_no_chained_cause(home: Path, tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path / ("a" * 300 + ".yaml"))
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


def test_home_config_dir_unreadable_is_exit_2(home: Path, alerts: Path) -> None:
    (home / ".sift" / "config.yaml").write_text("{}")
    with _mode000(home / ".sift"):
        result = CliRunner().invoke(app, ["validate", str(alerts)])
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    _one_line(result)


# --- 3. `sift config` write path ------------------------------------------------


def _bad_targets(tmp_path: Path) -> dict[str, Path]:
    valid = tmp_path / "valid.yaml"
    valid.write_text("{}")
    dangling = tmp_path / "dangling.yaml"
    dangling.symlink_to(tmp_path / "nowhere.yaml")
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    link = tmp_path / "link.yaml"
    link.symlink_to(valid)
    return {
        "missing_parent": tmp_path / "nodir" / "x.yaml",
        "dangling_symlink": dangling,
        "symlink_loop": loop,
        "symlink_to_valid": link,
        "dev_null": Path("/dev/null"),
    }


@pytest.mark.parametrize("kind", ["missing_parent", "dangling_symlink", "symlink_loop", "symlink_to_valid", "dev_null"])
def test_config_write_to_bad_target_is_exit_2(kind: str, home: Path, tmp_path: Path) -> None:
    target = _bad_targets(tmp_path)[kind]
    result = CliRunner().invoke(app, ["config", "--provider", "mock", "--config", str(target)])
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    assert "cannot" in _one_line(result)


@pytest.mark.parametrize("kind", ["missing_parent", "dangling_symlink", "symlink_loop", "symlink_to_valid", "dev_null"])
def test_bad_target_writes_no_credential_first(kind: str, home: Path, tmp_path: Path) -> None:
    target = _bad_targets(tmp_path)[kind]
    result = CliRunner().invoke(
        app, ["config", "--api-key", "sk-FAKE-KEY", "--provider", "mock", "--config", str(target)]
    )
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    assert not (home / ".sift" / ".env").exists()
    assert "sk-FAKE-KEY" not in result.stderr + result.stdout


def test_bad_target_writes_no_ticket_token_first(home: Path, tmp_path: Path) -> None:
    target = _bad_targets(tmp_path)["missing_parent"]
    result = CliRunner().invoke(
        app,
        ["config", "--ticket-provider", "thehive", "--ticket-token", "tok-FAKE", "--config", str(target)],
    )
    assert result.exit_code == 2
    assert not (home / ".sift" / ".env").exists()


def test_save_failure_after_a_clean_precheck_is_exit_2(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(config_mod, "save_config", boom)
    result = CliRunner().invoke(app, ["config", "--provider", "mock", "--config", str(tmp_path / "ok.yaml")])
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    assert "cannot write config" in _one_line(result)


def test_credentials_write_failure_is_exit_2(home: Path, tmp_path: Path) -> None:
    real = tmp_path / "real.env"
    real.write_text("")
    (home / ".sift" / ".env").symlink_to(real)  # refused by the writer
    result = CliRunner().invoke(app, ["config", "--api-key", "sk-FAKE-KEY"])
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    assert "cannot write" in _one_line(result)
    assert real.read_text() == ""


def test_credentials_clear_on_non_utf8_env_is_exit_2(home: Path) -> None:
    # the .env load error (exit 2) fires first; the writer path must not traceback either
    (home / ".sift" / ".env").write_bytes(b"SIFT_LLM_KEY=\xff\n")
    result = CliRunner().invoke(app, ["config", "--unset-api-key"])
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    _one_line(result)


# --- 4. unreadable explicit --config: one line, not click's panel ---------------


@pytest.mark.parametrize("command", COMMANDS)
def test_unreadable_explicit_config_is_one_line(command: str, home: Path, tmp_path: Path, alerts: Path) -> None:
    cfg = tmp_path / "unread.yaml"
    cfg.write_text("{}")
    with _mode000(cfg):
        result = CliRunner().invoke(app, _argv(command, alerts, cfg))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    line = _one_line(result)
    assert "cannot be read" in line and "Invalid value" not in result.stderr


# --- 5. RecursionError and no chained cause -------------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_deeply_nested_config_through_cli_is_one_line(command: str, home: Path, tmp_path: Path, alerts: Path) -> None:
    cfg = tmp_path / "deep.yaml"
    cfg.write_text("[" * 100000)
    result = CliRunner().invoke(app, _argv(command, alerts, cfg))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    _one_line(result)


def test_recursion_error_clause_is_pinned(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_f):
        raise RecursionError

    monkeypatch.setattr(config_mod.yaml, "safe_load", boom)
    f = tmp_path / "x.yaml"
    f.write_text("{}")
    with pytest.raises(ConfigError):
        load_config(f)


@pytest.mark.parametrize("kind", ["directory", "bad_date", "deep", "unreadable"])
def test_no_chained_cause_for_every_load_clause(kind: str, home: Path, tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    if kind == "directory":
        f = tmp_path
    elif kind == "bad_date":
        f.write_text("summarize:\n  model: 2020-13-45\n")
    elif kind == "deep":
        f.write_text("[" * 100000)
    else:
        f.write_text("{}")
    ctx = _mode000(f) if kind == "unreadable" else _nullcontext()
    with ctx, pytest.raises(ConfigError) as ei:
        load_config(f)
    assert ei.value.__cause__ is None
    assert ei.value.__suppress_context__ or ei.value.__context__ is None


@contextmanager
def _nullcontext() -> Iterator[None]:
    yield


# --- 6. legacy notice ------------------------------------------------------------


def test_legacy_notice_is_exactly_one_stderr_line_with_a_true_remedy(home: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "legacy.yaml"
    cfg.write_text("redaction:\n  redact_raw: true\n")
    proc = _run_real(["config", "--show", "--config", str(cfg)], home)
    assert proc.returncode == 0, proc.stderr
    lines = [ln for ln in proc.stderr.splitlines() if ln.strip()]
    assert len(lines) == 1, proc.stderr
    assert "FutureWarning" in lines[0] and "keep_raw" in lines[0]
    assert "any setting flag" in lines[0]
    assert "inspect" not in proc.stderr and "lineno" not in proc.stderr
    # the remedy is true: any setting flag rewrites the file with the new key
    proc2 = _run_real(["config", "--quiet", "--config", str(cfg)], home)
    assert proc2.returncode == 0, proc2.stderr
    on_disk = yaml.safe_load(cfg.read_text())
    assert on_disk["redaction"]["keep_raw"] is True and "redact_raw" not in on_disk["redaction"]


def test_bare_sift_config_rewrites_nothing(home: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "legacy.yaml"
    cfg.write_text("redaction:\n  redact_raw: true\n")
    before = cfg.read_text()
    result = CliRunner().invoke(app, ["config", "--config", str(cfg)])
    assert result.exit_code == 0 and cfg.read_text() == before


# --- 7. create-on-missing -----------------------------------------------------------


def test_config_create_starts_from_defaults_not_home_config(home: Path, tmp_path: Path) -> None:
    (home / ".sift" / "config.yaml").write_text(yaml.dump({"redaction": {"fields": ["user"]}}))
    target = tmp_path / "typo.yaml"
    result = CliRunner().invoke(app, ["config", "--provider", "template", "--config", str(target)])
    assert result.exit_code == 0, (result.stderr, result.exception)
    assert yaml.safe_load(target.read_text())["redaction"]["fields"] == []
    assert "created new config" in result.stderr and "saved" not in result.stderr.lower()


def test_config_update_of_existing_file_says_saved(home: Path, tmp_path: Path) -> None:
    target = tmp_path / "there.yaml"
    target.write_text("{}")
    result = CliRunner().invoke(app, ["config", "--provider", "template", "--config", str(target)])
    assert result.exit_code == 0
    assert "Config saved to" in result.stderr and "created new config" not in result.stderr


# --- 8. control characters in paths ---------------------------------------------------

EVIL = "x\033]0;PWNED\007\nsift: forged ok \x85.yaml"


@pytest.mark.parametrize("command", COMMANDS)
def test_control_chars_in_path_never_reach_stderr(command: str, home: Path, alerts: Path) -> None:
    result = CliRunner().invoke(app, _argv(command, alerts, EVIL))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    line = _one_line(result)
    for bad in ("\033", "\007", "\r", " ", "\x85"):
        assert bad not in result.stderr
    assert "\\x1b" in line and "\\x07" in line and "\\x0a" in line


def test_safe_path_escapes_controls_and_surrogates() -> None:
    s = config_mod._safe_path(Path("a\x00b\x1b\x7f\x9b \ud800c"))
    assert s == "a\\x00b\\x1b\\x7f\\x9b\\u2029\\ud800c"
    assert config_mod._safe_path(Path("plain/ü.yaml")) == "plain/ü.yaml"


def test_control_chars_in_real_console_stderr(home: Path, alerts: Path) -> None:
    proc = _run_real(["validate", str(alerts), "--config", EVIL], home)
    assert proc.returncode == 2
    assert len([ln for ln in proc.stderr.splitlines() if ln.strip()]) == 1
    assert "\033" not in proc.stderr and "\007" not in proc.stderr


# --- 9. non-regular --config (FIFO would block forever) -------------------------------


def test_fifo_config_is_rejected_not_hung(home: Path, tmp_path: Path, alerts: Path) -> None:
    fifo = tmp_path / "pipe.yaml"
    os.mkfifo(fifo)
    for argv in (["validate", str(alerts), "--config", str(fifo)], ["config", "--show", "--config", str(fifo)]):
        proc = _run_real(argv, home, timeout=20)
        assert proc.returncode == 2, (proc.returncode, proc.stderr)
        assert len([ln for ln in proc.stderr.splitlines() if ln.strip()]) == 1
        assert "not a regular file" in proc.stderr


def test_fifo_home_config_is_rejected_not_hung(home: Path, alerts: Path) -> None:
    os.mkfifo(home / ".sift" / "config.yaml")
    proc = _run_real(["validate", str(alerts)], home, timeout=20)
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    assert "not a regular file" in proc.stderr


def test_fifo_env_file_is_rejected_not_hung(home: Path, alerts: Path) -> None:
    os.mkfifo(home / ".sift" / ".env")
    proc = _run_real(["validate", str(alerts)], home, timeout=20)
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    assert "not a regular file" in proc.stderr


def test_dev_null_config_is_not_a_regular_file(home: Path) -> None:
    with pytest.raises(ConfigError) as ei:
        load_config(Path("/dev/null"))
    assert "not a regular file" in str(ei.value)
