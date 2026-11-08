"""Every `--help` must work, print once, and not need an undeclared `click`.

Regression: `triage --help` / `--help-all` did `import click` (not a declared
dependency; only transitive via typer). A lock without click crashed both with
ModuleNotFoundError while the old test (`--on-llm-failure` not in stdout)
stayed green because a crash satisfies it.
"""

from __future__ import annotations

import ast
import re
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


def _is_click_name(name: str) -> bool:
    return name == "click" or name.startswith("click.")


def _is_vendored_click(name: str) -> bool:
    return name == "typer._click" or name.startswith("typer._click.")


def find_click_imports(source: str) -> list[int]:
    """Line numbers of static, dynamic or vendored click imports in `source`."""
    hits: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            if any(_is_click_name(a.name) or _is_vendored_click(a.name) for a in node.names):
                hits.append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                continue
            mod = node.module or ""
            if _is_click_name(mod) or _is_vendored_click(mod):
                hits.append(node.lineno)
            elif mod == "typer" and any(a.name == "_click" for a in node.names):
                hits.append(node.lineno)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                called = func.attr
            elif isinstance(func, ast.Name):
                called = func.id
            else:
                continue
            if called not in {"import_module", "__import__"} or not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if _is_click_name(first.value) or _is_vendored_click(first.value):
                    hits.append(node.lineno)
    return hits


@pytest.mark.parametrize(
    "source",
    [
        "import click",
        "import click.utils",
        "from click import echo",
        "from click.utils import echo",
        "import importlib\nimportlib.import_module('click')",
        "import importlib\nimportlib.import_module('click.utils')",
        "from importlib import import_module\nimport_module('click')",
        "__import__('click')",
        "__import__('click.core')",
        "from typer import _click",
        "from typer._click import echo",
        "import typer._click",
        "import importlib\nimportlib.import_module('typer._click')",
        "def f():\n    import click\n",
    ],
)
def test_detector_flags_bad_forms(source: str) -> None:
    assert find_click_imports(source) != []


@pytest.mark.parametrize(
    "source",
    [
        "import typer",
        "import typer\ntyper.echo('x')",
        "from typer import Exit",
        '"""Click here to continue."""',
        "x = 'click'",
        "import importlib\nimportlib.import_module('clicker')",
        "import importlib\nimportlib.import_module('json')",
        "__import__('os')",
        "from . import click_helpers",
    ],
)
def test_detector_ignores_benign_forms(source: str) -> None:
    assert find_click_imports(source) == []


def test_no_module_under_sift_imports_click() -> None:
    offenders: list[str] = []
    for path in sorted(SIFT_PKG.rglob("*.py")):
        for lineno in find_click_imports(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(SIFT_PKG.parent)}:{lineno}")
    assert offenders == [], f"undeclared dependency click imported at: {offenders}"


_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _usage_line(output: str) -> str:
    plain = _ANSI.sub("", output)
    for line in plain.splitlines():
        if line.strip().startswith("Usage:"):
            return line.strip()
    raise AssertionError(f"no 'Usage:' line found in help output: {plain!r}")


@pytest.mark.parametrize("name", _command_names())
def test_usage_line_has_no_placeholder_token(name: str) -> None:
    """typer 0.27 prints a bare argument as `{files}...`; keep a plain metavar."""
    usage = _usage_line(runner.invoke(app, [name, "--help"]).output)
    assert "{" not in usage and "}" not in usage, usage


def test_triage_usage_line_ends_with_files() -> None:
    usage = _usage_line(runner.invoke(app, ["triage", "--help"]).output)
    assert usage.endswith("FILES..."), usage
