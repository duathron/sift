"""
sift/doctor.py — Diagnostic checks for the sift environment.

Runs a series of named checks and reports PASS / WARN / FAIL status via a
Rich table.  Only stdlib, rich, and pydantic are used here; optional
dependencies (anthropic, openai, barb, vex) are probed at runtime via
importlib so that missing packages never crash the doctor command.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import urllib.error
import urllib.request
from enum import Enum
from pathlib import Path

from pydantic import BaseModel
from rich import box
from rich.console import Console
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_PATH = Path.home() / ".sift" / "config.yaml"
OUTPUT_DIR = Path.home() / ".sift"
CACHE_DIR = Path.home() / ".sift" / "cache"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"
OLLAMA_TIMEOUT_S = 2

MIN_PYTHON_MAJOR = 3
MIN_PYTHON_MINOR = 12

LLM_INSTALL_HINT = r"Not installed – run: pip install sift-triage\[llm]"
ENRICH_INSTALL_HINT = r"Not installed – run: pip install sift-triage\[enrich]"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class CheckStatus(str, Enum):
    """Outcome of a single diagnostic check."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class CheckResult(BaseModel):
    """Result of a single named diagnostic check."""

    name: str
    status: CheckStatus
    message: str = ""


# ---------------------------------------------------------------------------
# Individual check helpers
# ---------------------------------------------------------------------------


def _check_python_version() -> CheckResult:
    """Verify that the running Python is at least 3.12."""
    major, minor = sys.version_info.major, sys.version_info.minor
    version_str = f"{major}.{minor}.{sys.version_info.micro}"
    if (major, minor) >= (MIN_PYTHON_MAJOR, MIN_PYTHON_MINOR):
        return CheckResult(
            name="Python version",
            status=CheckStatus.PASS,
            message=version_str,
        )
    return CheckResult(
        name="Python version",
        status=CheckStatus.FAIL,
        message=f"{version_str} – sift requires Python {MIN_PYTHON_MAJOR}.{MIN_PYTHON_MINOR}+",
    )


def _check_config_file() -> CheckResult:
    """Verify that ~/.sift/config.yaml exists."""
    if CONFIG_PATH.exists():
        return CheckResult(
            name="Config file",
            status=CheckStatus.PASS,
            message=str(CONFIG_PATH),
        )
    return CheckResult(
        name="Config file",
        status=CheckStatus.WARN,
        message="Using defaults (no config file found)",
    )


def _check_importable(package: str) -> bool:
    """Return True if *package* can be imported without actually importing it."""
    return importlib.util.find_spec(package) is not None


def _check_llm_anthropic() -> CheckResult:
    """Check whether the anthropic package is installed."""
    if _check_importable("anthropic"):
        return CheckResult(name="LLM: Anthropic", status=CheckStatus.PASS)
    return CheckResult(
        name="LLM: Anthropic",
        status=CheckStatus.WARN,
        message=LLM_INSTALL_HINT,
    )


def _check_llm_openai() -> CheckResult:
    """Check whether the openai package is installed."""
    if _check_importable("openai"):
        return CheckResult(name="LLM: OpenAI", status=CheckStatus.PASS)
    return CheckResult(
        name="LLM: OpenAI",
        status=CheckStatus.WARN,
        message=LLM_INSTALL_HINT,
    )


def _check_llm_ollama() -> CheckResult:
    """Probe the local Ollama daemon by hitting its /api/tags endpoint."""
    try:
        with urllib.request.urlopen(OLLAMA_TAGS_URL, timeout=OLLAMA_TIMEOUT_S):
            pass
        return CheckResult(name="LLM: Ollama (local)", status=CheckStatus.PASS)
    except (urllib.error.URLError, OSError):
        return CheckResult(
            name="LLM: Ollama (local)",
            status=CheckStatus.WARN,
            message="Ollama not running",
        )


def _check_enrich_barb() -> CheckResult:
    """Check whether the barb-phish package (module: barb) is installed."""
    if _check_importable("barb"):
        return CheckResult(name="Enrichment: barb", status=CheckStatus.PASS)
    return CheckResult(
        name="Enrichment: barb",
        status=CheckStatus.WARN,
        message=ENRICH_INSTALL_HINT,
    )


def _check_enrich_vex() -> CheckResult:
    """Check whether the vex-ioc package (module: vex) is installed."""
    if _check_importable("vex"):
        return CheckResult(name="Enrichment: vex", status=CheckStatus.PASS)
    return CheckResult(
        name="Enrichment: vex",
        status=CheckStatus.WARN,
        message=ENRICH_INSTALL_HINT,
    )


def _check_llm_key() -> CheckResult:
    """Check whether an LLM API key is available (env var or ~/.sift/.env)."""
    key = os.environ.get("SIFT_LLM_KEY", "")
    source = "env var"
    if not key:
        env_file = Path.home() / ".sift" / ".env"
        if env_file.exists():
            try:
                from dotenv import dotenv_values
                key = dotenv_values(env_file).get("SIFT_LLM_KEY", "") or ""
                source = "~/.sift/.env"
            except ImportError:
                pass
    if key:
        masked = f"****{key[-4:]}" if len(key) >= 4 else "****"
        return CheckResult(
            name="LLM API key",
            status=CheckStatus.PASS,
            message=f"{masked} (via {source})",
        )
    return CheckResult(
        name="LLM API key",
        status=CheckStatus.WARN,
        message="Not set – run: sift config --api-key <key>",
    )


def _check_output_directory() -> CheckResult:
    """Check whether ~/.sift/ exists and is writable."""
    if OUTPUT_DIR.exists() and os.access(OUTPUT_DIR, os.W_OK):
        return CheckResult(
            name="Output directory",
            status=CheckStatus.PASS,
            message=str(OUTPUT_DIR),
        )
    if not OUTPUT_DIR.exists():
        message = f"{OUTPUT_DIR} does not exist"
    else:
        message = f"{OUTPUT_DIR} is not writable"
    return CheckResult(
        name="Output directory",
        status=CheckStatus.FAIL,
        message=message,
    )


def _check_llm_schema_validation() -> CheckResult:
    """Check that LLM schema validation module is available."""
    if _check_importable("sift.summarizers.validation"):
        return CheckResult(
            name="LLM schema validation",
            status=CheckStatus.PASS,
            message="Validation module available",
        )
    return CheckResult(
        name="LLM schema validation",
        status=CheckStatus.WARN,
        message="Validation module not found",
    )


def _check_cache_directory() -> CheckResult:
    """Check whether ~/.sift/cache/ is accessible and writable."""
    if not CACHE_DIR.exists():
        return CheckResult(
            name="Result cache",
            status=CheckStatus.WARN,
            message="Result cache: not initialized (use --cache to enable)",
        )
    if os.access(CACHE_DIR, os.W_OK):
        return CheckResult(
            name="Result cache",
            status=CheckStatus.PASS,
            message="Result cache: ready",
        )
    return CheckResult(
        name="Result cache",
        status=CheckStatus.WARN,
        message=f"Result cache: permission error at {CACHE_DIR}",
    )


def _check_ticketing() -> CheckResult:
    """Check ticketing provider config and connectivity (optional feature)."""
    try:
        from sift.config import load_config
        cfg = load_config()
    except Exception:
        return CheckResult(name="Ticketing", status=CheckStatus.WARN, message="Could not load config")

    provider = cfg.ticketing.provider
    if not provider:
        return CheckResult(
            name="Ticketing",
            status=CheckStatus.INFO if hasattr(CheckStatus, "INFO") else CheckStatus.WARN,
            message="No default provider set — optional (use: sift config --ticket-provider)",
        )

    try:
        from sift.ticketing import build_provider
        tp = build_provider(provider, cfg)
        ok, msg = tp.healthcheck()
        return CheckResult(
            name=f"Ticketing: {provider}",
            status=CheckStatus.PASS if ok else CheckStatus.FAIL,
            message=msg,
        )
    except ValueError as exc:
        return CheckResult(
            name=f"Ticketing: {provider}",
            status=CheckStatus.WARN,
            message=str(exc),
        )
    except ImportError:
        return CheckResult(
            name="Ticketing",
            status=CheckStatus.WARN,
            message=r"httpx not installed — run: pip install sift-triage\[ticket]",
        )
    except Exception as exc:
        return CheckResult(
            name=f"Ticketing: {provider}",
            status=CheckStatus.FAIL,
            message=str(exc),
        )


def _check_attck_module() -> CheckResult:
    """Check that the ATT&CK technique validation module works correctly."""
    try:
        from sift.pipeline.attck import TECHNIQUE_PATTERN, is_valid_technique_id  # noqa: F401

        assert is_valid_technique_id("T1566")
        assert is_valid_technique_id("T1566.001")
        assert not is_valid_technique_id("invalid")
        return CheckResult(
            name="ATT&CK validation",
            status=CheckStatus.PASS,
            message="ATT&CK validation: technique ID module loaded",
        )
    except Exception as exc:
        return CheckResult(
            name="ATT&CK validation",
            status=CheckStatus.WARN,
            message=f"ATT&CK validation: module unavailable ({exc})",
        )


def _check_stix_export() -> CheckResult:
    """Check that the STIX 2.1 export module imports cleanly."""
    try:
        from sift.output.stix import STIXExporter  # noqa: F401

        return CheckResult(
            name="STIX 2.1 export",
            status=CheckStatus.PASS,
            message="STIX 2.1 export: available",
        )
    except Exception:
        return CheckResult(
            name="STIX 2.1 export",
            status=CheckStatus.WARN,
            message="STIX 2.1 export: module import failed",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_checks() -> list[CheckResult]:
    """Run all diagnostic checks and return a list of :class:`CheckResult`.

    Checks are executed in a fixed, human-readable order.  Each check is
    independent; a failure in one never prevents the others from running.
    """
    return [
        _check_python_version(),
        _check_config_file(),
        _check_llm_anthropic(),
        _check_llm_openai(),
        _check_llm_ollama(),
        _check_enrich_barb(),
        _check_enrich_vex(),
        _check_llm_key(),
        _check_output_directory(),
        _check_llm_schema_validation(),
        _check_cache_directory(),
        _check_stix_export(),
        _check_attck_module(),
        _check_ticketing(),
    ]


def print_doctor_report(
    results: list[CheckResult],
    console: Console | None = None,
) -> bool:
    """Render a Rich table summarising all check results.

    Parameters
    ----------
    results:
        The list returned by :func:`run_checks`.
    console:
        An existing :class:`rich.console.Console` instance.  A new one is
        created if *None* is passed.

    Returns
    -------
    bool
        ``True`` when every check passed or warned (i.e. no FAIL results),
        ``False`` if at least one check has status FAIL.
    """
    if console is None:
        console = Console()

    _STATUS_STYLE: dict[CheckStatus, str] = {
        CheckStatus.PASS: "bold green",
        CheckStatus.WARN: "bold yellow",
        CheckStatus.FAIL: "bold red",
    }

    table = Table(
        title="sift doctor",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    table.add_column("Status", justify="center", min_width=6, no_wrap=True)
    table.add_column("Check", min_width=28)
    table.add_column("Details", min_width=40)

    has_fail = False
    warn_count = 0
    for result in results:
        style = _STATUS_STYLE[result.status]
        table.add_row(
            f"[{style}]{result.status.value}[/{style}]",
            result.name,
            result.message,
        )
        if result.status is CheckStatus.FAIL:
            has_fail = True
        elif result.status is CheckStatus.WARN:
            warn_count += 1

    console.print()
    console.print(table)
    console.print()

    if has_fail:
        console.print(
            "[bold red]One or more checks FAILED.[/bold red] "
            "Resolve the issues above before running sift.\n"
        )
    elif warn_count > 0:
        console.print(
            f"[bold green]All checks passed[/bold green] "
            f"[yellow]({warn_count} warning(s) — optional features unavailable).[/yellow]\n"
        )
    else:
        console.print("[bold green]All checks passed.[/bold green]\n")

    return not has_fail
