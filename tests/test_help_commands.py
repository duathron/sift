"""Every `--help` must work, print once, and not need an undeclared `click`.

Regression: `triage --help` / `--help-all` did `import click` (not a declared
dependency; only transitive via typer). A lock without click crashed both with
ModuleNotFoundError while the old test (`--on-llm-failure` not in stdout)
stayed green because a crash satisfies it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import typer.main
from typer.testing import CliRunner

from sift.main import app

runner = CliRunner()

SIFT_PKG = Path(__file__).resolve().parent.parent / "sift"


def _command_names() -> list[str]:
    group = typer.main.get_command(app)
    return sorted(group.commands)  # type: ignore[attr-defined]


def _assert_clean_help(result) -> None:
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(result.exception)
    assert result.exit_code == 0, result.output
    assert result.output.count("Usage:") == 1, result.output


def test_command_discovery_is_not_empty() -> None:
    assert {"triage", "validate", "doctor", "metrics", "config", "version"} <= set(_command_names())


def test_root_help() -> None:
    _assert_clean_help(runner.invoke(app, ["--help"]))


@pytest.mark.parametrize("name", _command_names())
def test_command_help(name: str) -> None:
    result = runner.invoke(app, [name, "--help"])
    _assert_clean_help(result)
    if name == "triage":
        assert "Current Setup" in result.output


def test_triage_help_all_shows_setup_panel_and_hidden_flags() -> None:
    plain = runner.invoke(app, ["triage", "--help"])
    result = runner.invoke(app, ["triage", "--help-all"])
    _assert_clean_help(result)
    assert "Current Setup" in result.output
    assert len(result.output) > len(plain.output)


def test_no_module_under_sift_imports_click() -> None:
    offenders: list[str] = []
    for path in sorted(SIFT_PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] if node.level == 0 else []
            else:
                continue
            if any(n == "click" or n.startswith("click.") for n in names):
                offenders.append(f"{path.relative_to(SIFT_PKG.parent)}:{node.lineno}")
    assert offenders == [], f"undeclared dependency click imported at: {offenders}"
