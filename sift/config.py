"""Configuration system for sift.

Priority hierarchy: CLI flags > env vars > ~/.sift/config.yaml > defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel

_APP_DIR = Path.home() / ".sift"
_DIR_MODE = 0o700
_FILE_MODE = 0o600


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
    sub_chunk_size: int = 100_000      # alerts per sub-chunk batch (within a single large file)


class SummarizeConfig(BaseModel):
    """AI summarization configuration."""

    provider: str = "template"      # template | anthropic | openai | ollama
    model: Optional[str] = None     # None = auto-select per provider
    api_key: Optional[str] = None   # or SIFT_LLM_KEY env var
    max_tokens: int = 1000
    temperature: float = 0.1
    redact_fields: list[str] = []   # field names to strip before LLM submission


class OutputConfig(BaseModel):
    default_format: str = "rich"    # rich | console | json | csv
    quiet: bool = False


class EnrichConfig(BaseModel):
    """Settings for --enrich mode."""

    consent_given: bool = False     # skip consent prompt when True


class UpdateCheckConfig(BaseModel):
    enabled: bool = True
    check_interval_hours: int = 24


class PromptInjectionConfig(BaseModel):
    """Configuration for prompt injection detection and prevention."""

    enabled: bool = True              # Enable/disable injection detection
    whitelist_patterns: list[str] = []  # Optional regex patterns for safe content


class AlertRedactionConfig(BaseModel):
    """Configuration for alert-model-level field redaction."""

    fields: list[str] = []      # field names to redact on the Alert object
    redact_raw: bool = False     # if True, always redact the `raw` dict


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
    cache_enabled: bool = True   # Result caching on by default (use --no-cache to disable)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _ensure_app_dir() -> Path:
    _APP_DIR.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    return _APP_DIR


def load_config(config_path: Optional[Path] = None) -> AppConfig:
    """Load configuration from YAML with env var overrides.

    Priority: CLI flags > env vars > ~/.sift/.env > ~/.sift/config.yaml > defaults.
    """
    # Load credentials from ~/.sift/.env before reading SIFT_LLM_KEY from environment.
    _env_file = _APP_DIR / ".env"
    if _env_file.exists():
        from dotenv import load_dotenv
        load_dotenv(_env_file, override=False)

    data: dict = {}
    paths = [p for p in [config_path, _APP_DIR / "config.yaml", Path("config.yaml")] if p and p.exists()]
    if paths:
        with open(paths[0]) as f:
            data = yaml.safe_load(f) or {}

    config = AppConfig(**data)

    # Env var overrides (includes values just loaded from ~/.sift/.env)
    llm_key = os.getenv("SIFT_LLM_KEY")
    if llm_key:
        config.summarize.api_key = llm_key

    return config


def save_config(config: AppConfig, path: Optional[Path] = None) -> Path:
    """Persist config to YAML file (never writes api_key — stored in ~/.sift/.env)."""
    target = path or (_ensure_app_dir() / "config.yaml")
    with open(target, "w") as f:
        # Exclude api_key from persisted config — secrets must not be written to disk.
        data = config.model_dump(exclude={"summarize": {"api_key"}})
        yaml.dump(data, f, default_flow_style=False)
    target.chmod(_FILE_MODE)
    return target


def save_credentials(api_key: str) -> Path:
    """Store the LLM API key in ~/.sift/.env (mode 600, never in config.yaml)."""
    env_path = _ensure_app_dir() / ".env"
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    lines = [l for l in lines if not l.startswith("SIFT_LLM_KEY=")]
    lines.append(f"SIFT_LLM_KEY={api_key}")
    env_path.write_text("\n".join(lines) + "\n")
    env_path.chmod(_FILE_MODE)
    return env_path


def clear_credentials() -> bool:
    """Remove SIFT_LLM_KEY from ~/.sift/.env. Returns True if key was present."""
    env_path = _APP_DIR / ".env"
    if not env_path.exists():
        return False
    lines = env_path.read_text().splitlines()
    new_lines = [l for l in lines if not l.startswith("SIFT_LLM_KEY=")]
    if len(new_lines) == len(lines):
        return False
    env_path.write_text("\n".join(new_lines) + "\n")
    return True
