"""A bad or missing config is reported in one value-free line with exit code 2, never a traceback."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from sift.main import app

SECRET = "sk-LEAKME-123"

# name -> raw bytes of the config file
BAD_CONFIGS = {
    "bad_yaml": f"summarize:\n  api_key: {SECRET}\n  : [unclosed\n".encode(),
    "non_mapping": f"- {SECRET}\n".encode(),
    "falsy_non_mapping": b"[]\n",
    "schema_error": yaml.dump({"clustering": {"time_window_minutes": SECRET}}).encode(),
    "non_utf8": b"summarize:\n  api_key: " + SECRET.encode() + b"\xff\xfe\n",
}
COMMANDS = ["triage", "validate", "metrics", "config"]


def _argv(command: str, alerts: Path, cfg: Path) -> list[str]:
    if command == "config":
        return ["config", "--show", "--config", str(cfg)]
    return [command, str(alerts), "--config", str(cfg)]


@pytest.fixture
def alerts(tmp_path: Path) -> Path:
    f = tmp_path / "alerts.json"
    f.write_text("[]")
    return f


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("SIFT_LLM_KEY", raising=False)


def _assert_one_clean_line(stderr: str, stdout: str) -> None:
    assert SECRET not in stderr + stdout
    assert "Traceback" not in stderr + stdout
    assert "0xff" not in stderr + stdout
    lines = [line for line in stderr.splitlines() if line.strip()]
    assert len(lines) == 1, stderr
    assert "config" in lines[0]


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("kind", sorted(BAD_CONFIGS))
def test_cli_runner_bad_config_one_line_exit_2(command: str, kind: str, tmp_path: Path, alerts: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_bytes(BAD_CONFIGS[kind])
    result = CliRunner().invoke(app, _argv(command, alerts, cfg))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    _assert_one_clean_line(result.stderr, result.stdout)


def test_config_command_may_create_a_new_config_file(tmp_path: Path) -> None:
    target = tmp_path / "new.yaml"
    result = CliRunner().invoke(app, ["config", "--quiet", "--config", str(target)])
    assert result.exit_code == 0, (result.stderr, result.exception)
    assert target.exists()


@pytest.mark.parametrize("command", COMMANDS)
def test_cli_runner_missing_explicit_config_exit_2(command: str, tmp_path: Path, alerts: Path) -> None:
    sift_dir = tmp_path / "home" / ".sift"
    sift_dir.mkdir()
    (sift_dir / "config.yaml").write_text(yaml.dump({"redaction": {"fields": ["user"]}}))
    result = CliRunner().invoke(app, _argv(command, alerts, tmp_path / "typo.yaml"))
    assert result.exit_code == 2, (result.exit_code, result.stderr, result.exception)
    assert "not found" in result.stderr
    _assert_one_clean_line(result.stderr, result.stdout)


def _console_script() -> Path:
    script = Path(sys.executable).parent / "sift"
    if not script.exists():
        pytest.skip("console script not installed in this environment")
    return script


@pytest.mark.parametrize("kind", sorted(BAD_CONFIGS))
def test_real_console_script_bad_config(kind: str, tmp_path: Path, alerts: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_bytes(BAD_CONFIGS[kind])
    proc = subprocess.run(
        [str(_console_script()), *_argv("triage", alerts, cfg)],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "home")},
        timeout=60,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    _assert_one_clean_line(proc.stderr, proc.stdout)


def test_real_console_script_missing_config(tmp_path: Path, alerts: Path) -> None:
    proc = subprocess.run(
        [str(_console_script()), *_argv("validate", alerts, tmp_path / "typo.yaml")],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "home")},
        timeout=60,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    assert "not found" in proc.stderr
    _assert_one_clean_line(proc.stderr, proc.stdout)
