"""Configuration system for sift.

Priority hierarchy: CLI flags > env vars > ~/.sift/config.yaml > defaults.
Only ``--config`` and ``~/.sift/config.yaml`` are read; a ``config.yaml`` in the
current directory is never loaded (it may come from an untrusted download).
"""

from __future__ import annotations

import inspect
import os
import tempfile
import warnings
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, ValidationError, model_validator
from shipwright_kit.config import app_dir
from shipwright_kit.config import load_config as _resolve_config

_APP_DIR = app_dir("sift")  # path only; ~/.sift
_DIR_MODE = 0o700
_FILE_MODE = 0o600


class ConfigError(Exception):
    """A config file could not be used. The message never contains file contents."""


# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------


class SeverityWeights(BaseModel):
    """Numeric score per alert severity (used in cluster priority calculation)."""

    INFO: int = 1
    LOW: int = 2
    MEDIUM: int = 5
    HIGH: int = 10
    CRITICAL: int = 20


class PriorityThresholds(BaseModel):
    """Cluster score thresholds for priority assignment."""

    low: int = 5
    medium: int = 20
    high: int = 50
    critical: int = 100


class ScoringConfig(BaseModel):
    weights: SeverityWeights = SeverityWeights()
    thresholds: PriorityThresholds = PriorityThresholds()


class ClusteringConfig(BaseModel):
    """Alert clustering parameters."""

    time_window_minutes: int = 30
    max_cluster_size: int = 50
    chunk_size: int = 0  # 0 = no chunking; >0 = process in batches of this size
    sub_chunk_threshold_mb: int = 500  # files above this get automatic sub-file chunking
    sub_chunk_size: int = 100_000  # alerts per sub-chunk batch (within a single large file)
    # Auto-tuning thresholds (lifted from tuning.py module constants so users can override in config.yaml)
    drop_raw_threshold_mb: int = 500  # total input above this → drop raw dicts to save RAM
    chunk_threshold_mb: int = 200  # total input above this → enable chunking
    default_chunk_size: int = 100_000  # alerts per chunk when auto-chunking kicks in


class SummarizeConfig(BaseModel):
    """AI summarization configuration."""

    provider: str = "template"  # template | anthropic | openai | ollama
    model: Optional[str] = None  # None = auto-select per provider
    api_key: Optional[str] = None  # or SIFT_LLM_KEY env var
    max_tokens: int = 4096
    temperature: float = 0.1
    # Field names to strip from the LLM prompt only. The prompt also blanks cluster
    # label/reason/IOC text whenever this OR --redact-fields / redaction.fields is set.
    redact_fields: list[str] = []


class OutputConfig(BaseModel):
    default_format: str = "rich"  # rich | console | json | csv
    quiet: bool = False


class EnrichConfig(BaseModel):
    """Settings for --enrich mode."""

    consent_given: bool = False  # skip consent prompt when True


class UpdateCheckConfig(BaseModel):
    enabled: bool = True
    check_interval_hours: int = 24


class PromptInjectionConfig(BaseModel):
    """Configuration for prompt injection detection and prevention."""

    enabled: bool = True  # Enable/disable injection detection
    whitelist_patterns: list[str] = []  # Optional regex patterns for safe content
    verbose: bool = False  # Per-alert warning lines (default: quiet summary)
    log_file: Optional[str] = None  # Dump findings JSON to this path if set


class AlertRedactionConfig(BaseModel):
    """Configuration for alert-model-level field redaction."""

    fields: list[str] = []  # field names to redact on the Alert object
    keep_raw: bool = False  # if True, KEEP raw in output even when redaction is active (forensic override)

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_redact_raw(cls, data: Any) -> Any:
        """Map the old ``redact_raw`` key (which meant "keep raw") onto ``keep_raw``."""
        global _LEGACY_REDACT_RAW_WARNED
        if isinstance(data, dict) and "redact_raw" in data:
            data = dict(data)
            legacy = data.pop("redact_raw")
            data.setdefault("keep_raw", legacy)  # an explicit keep_raw wins
            if not _LEGACY_REDACT_RAW_WARNED:
                _LEGACY_REDACT_RAW_WARNED = True
                # warn_explicit: no stacklevel lands on user code from inside pydantic's validator
                # machinery, so name this module instead of a pydantic internal line.
                warnings.warn_explicit(
                    "config key redaction.redact_raw is renamed to redaction.keep_raw "
                    "(redact_raw: true meant KEEP raw output, so it now reads keep_raw: true); "
                    "the old name still works for now (run `sift config` to rewrite the file)",
                    FutureWarning,
                    filename=__file__,
                    lineno=inspect.currentframe().f_lineno,  # type: ignore[union-attr]
                    module=__name__,
                )
        return data

    @property
    def redact_raw(self) -> bool:
        """Read-only alias of ``keep_raw`` for code that still uses the old name."""
        return self.keep_raw


_LEGACY_REDACT_RAW_WARNED = False


class TicketingConfig(BaseModel):
    """Ticketing provider configuration (credentials stored separately in ~/.sift/.env)."""

    provider: Optional[str] = None  # thehive | jira | dry-run
    url: Optional[str] = None  # provider base URL
    project_key: Optional[str] = None  # Jira: project key
    jira_email: Optional[str] = None  # Jira: account email
    jira_issue_type: str = "Task"  # Jira: issue type
    thehive_tlp: int = 2  # TheHive: TLP (0–3, AMBER=2)
    timeout: float = 10.0  # HTTP request timeout (seconds)


class AppConfig(BaseModel):
    """Top-level application configuration."""

    clustering: ClusteringConfig = ClusteringConfig()
    scoring: ScoringConfig = ScoringConfig()
    summarize: SummarizeConfig = SummarizeConfig()
    output: OutputConfig = OutputConfig()
    enrich: EnrichConfig = EnrichConfig()
    update_check: UpdateCheckConfig = UpdateCheckConfig()
    injection: PromptInjectionConfig = PromptInjectionConfig()
    redaction: AlertRedactionConfig = AlertRedactionConfig()
    ticketing: TicketingConfig = TicketingConfig()
    cache_enabled: bool = True  # Result caching on by default (use --no-cache to disable)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _ensure_app_dir() -> Path:
    _APP_DIR.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    _APP_DIR.chmod(_DIR_MODE)  # also tightens a directory created earlier with a looser mode
    return _APP_DIR


def _write_private(path: Path, text: str) -> None:
    """Write *text* to *path* so it is never readable by anyone else, not even briefly.

    The data goes into a fresh 0600 temp file in the same directory and replaces
    *path* atomically, so a pre-existing loose-mode file is replaced rather than
    reused. A symlink at *path* is refused (it could redirect the write).
    """
    if path.is_symlink():
        raise OSError(f"refusing to write through a symlink: {path}")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, _FILE_MODE)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _load_yaml(path: Path) -> dict:
    # No cause is chained anywhere below: parser and decoder messages quote the offending
    # line or byte, which may hold a secret.
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        raise ConfigError(f"config file {path} is not valid YAML") from None
    except UnicodeDecodeError:
        raise ConfigError(f"config file {path} is not valid UTF-8 text") from None
    except OSError:
        raise ConfigError(f"config file {path} cannot be read") from None
    except (ValueError, RecursionError):
        # PyYAML leaks bare ValueError for e.g. an impossible date, RecursionError for deep nesting.
        raise ConfigError(f"config file {path} is not valid YAML") from None
    # An empty file or a bare `null` means "no settings" (defaults). Any other top level
    # that is not a mapping - including falsy ones such as [] 0 '' false - is an error.
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must be a mapping of settings at the top level")
    return data


def _validate(data: dict) -> AppConfig:
    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        # pydantic's own message echoes the rejected values; keep only where and why.
        bad = "; ".join(f"{'.'.join(str(p) for p in e['loc'])} ({e['type']})" for e in exc.errors())
        raise ConfigError(f"config has invalid settings: {bad}") from None


def load_config(config_path: Optional[Path] = None, *, must_exist: bool = True) -> AppConfig:
    """Load configuration from YAML with env var overrides.

    Priority: CLI flags > env vars > ~/.sift/.env > ~/.sift/config.yaml > defaults.

    An explicit *config_path* that does not exist raises ConfigError (``must_exist=False``
    is for ``sift config``, whose ``--config`` may name a file about to be created).
    """
    if must_exist and config_path is not None and not config_path.exists():
        # An explicit --config must never fall back silently to ~/.sift/config.yaml or defaults:
        # a typo would drop the operator's redaction and provider settings without a word.
        raise ConfigError(f"--config file not found: {config_path}")

    # Load credentials from ~/.sift/.env before reading SIFT_LLM_KEY from environment.
    _env_file = _APP_DIR / ".env"
    if _env_file.exists():
        from dotenv import load_dotenv

        load_dotenv(_env_file, override=False)

    config = _resolve_config(
        [config_path, _APP_DIR / "config.yaml"],
        loader=_load_yaml,
        validator=_validate,
    )

    # Env var overrides (includes values just loaded from ~/.sift/.env)
    llm_key = os.getenv("SIFT_LLM_KEY")
    if llm_key:
        config.summarize.api_key = llm_key

    return config


def save_config(config: AppConfig, path: Optional[Path] = None) -> Path:
    """Persist config to YAML file (never writes api_key — stored in ~/.sift/.env)."""
    target = path or (_ensure_app_dir() / "config.yaml")
    # Exclude api_key from persisted config — secrets must not be written to disk.
    data = config.model_dump(exclude={"summarize": {"api_key"}})
    _write_private(target, yaml.dump(data, default_flow_style=False))
    return target


def save_credentials(api_key: str) -> Path:
    """Store the LLM API key in ~/.sift/.env (mode 600, never in config.yaml)."""
    env_path = _ensure_app_dir() / ".env"
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    lines = [line for line in lines if not line.startswith("SIFT_LLM_KEY=")]
    lines.append(f"SIFT_LLM_KEY={api_key}")
    _write_private(env_path, "\n".join(lines) + "\n")
    return env_path


def save_ticket_token(token: str, provider: str) -> Path:
    """Store ticket provider token in ~/.sift/.env (mode 600).

    TheHive → SIFT_THEHIVE_TOKEN
    Jira    → SIFT_JIRA_TOKEN
    """
    env_key = "SIFT_THEHIVE_TOKEN" if provider == "thehive" else "SIFT_JIRA_TOKEN"
    env_path = _ensure_app_dir() / ".env"
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    lines = [line for line in lines if not line.startswith(f"{env_key}=")]
    lines.append(f"{env_key}={token}")
    _write_private(env_path, "\n".join(lines) + "\n")
    return env_path


def clear_credentials() -> bool:
    """Remove SIFT_LLM_KEY from ~/.sift/.env. Returns True if key was present."""
    env_path = _APP_DIR / ".env"
    if not env_path.exists():
        return False
    lines = env_path.read_text().splitlines()
    new_lines = [line for line in lines if not line.startswith("SIFT_LLM_KEY=")]
    if len(new_lines) == len(lines):
        return False
    _write_private(env_path, "\n".join(new_lines) + "\n")
    return True
