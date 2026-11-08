"""Configuration system for sift.

Priority hierarchy: CLI flags > env vars > ~/.sift/config.yaml > defaults.
Only ``--config`` and ``~/.sift/config.yaml`` are read; a ``config.yaml`` in the
current directory is never loaded (it may come from an untrusted download).
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
import unicodedata
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


# Unicode general categories that are never shown raw: Cc controls (C0, DEL, C1), Cf format
# characters (bidi overrides and isolates U+202A-202E / U+2066-2069, zero-width U+200B-200F,
# U+061C, U+FEFF, U+00AD, U+2060, tag characters U+E0000+), Cs lone surrogates (undecodable
# argv bytes), Zl/Zp line and paragraph separators (U+2028/2029).
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def _safe_path(path: Any) -> str:
    """Render *path* for a one-line message: control, format and separator characters become escapes.

    A path comes from the operator (``--config``) and may hold ESC/BEL/CR/LF, bidi overrides,
    zero-width characters or undecodable bytes. Printed raw they could retitle the terminal,
    forge a second ``sift:`` line or make the path read as a different one.
    """
    out: list[str] = []
    for ch in str(path):
        o = ord(ch)
        if unicodedata.category(ch) in _ESCAPED_CATEGORIES:
            out.append(f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}")
        else:
            out.append(ch)
    return "".join(out)


_MISSING_ERRNOS = (errno.ENOENT, errno.ENOTDIR, errno.ELOOP)


def _stat_config_file(path: Path, what: str) -> bool:
    """True if *path* is a regular file, False if it does not exist; ConfigError otherwise.

    One ``os.stat`` mapped by errno, so a permission or name-length failure is a ConfigError
    on every Python version (``Path.exists`` raises on some and swallows on others), and a
    FIFO or device is refused instead of blocking or reading forever.
    """
    try:
        st = os.stat(path)
    except OSError as exc:
        if exc.errno in _MISSING_ERRNOS:
            return False
        raise ConfigError(f"{what} {_safe_path(path)} cannot be read") from None
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{what} {_safe_path(path)} cannot be read (not a regular file)")
    return True


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
                # machinery, so name this module; lineno 0 keeps the notice to one stderr line.
                warnings.warn_explicit(
                    "config key redaction.redact_raw is renamed to redaction.keep_raw "
                    "(redact_raw: true meant KEEP raw output, so it now reads keep_raw: true); "
                    "the old name still works for now (edit the file, or run `sift config` with any setting flag "
                    "to rewrite it)",
                    FutureWarning,
                    filename=__file__,
                    lineno=0,  # 0 = no source line is quoted under the notice
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


def _after_parent_pinned() -> None:
    """Seam for tests: runs once the target directory is pinned, before anything is written."""


def _dir_fd_supported() -> bool:
    return (
        os.open in os.supports_dir_fd
        and os.rename in os.supports_dir_fd  # os.replace is rename(2) and takes the same dir_fd arguments
        and os.unlink in os.supports_dir_fd
        and os.stat in os.supports_dir_fd  # os.lstat itself is not listed on 3.11; stat(follow_symlinks=False) is it
        and os.stat in os.supports_follow_symlinks
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


_DIR_FD_OK = _dir_fd_supported()  # decided once at import, before anything can wrap os.unlink and friends


def _write_private(path: Path, text: str) -> None:
    """Write *text* to *path* so it is never readable by anyone else, not even briefly.

    The data goes into a fresh 0600 temp file in the same directory and replaces *path*
    atomically, so a pre-existing loose-mode file is replaced rather than reused. The leaf
    is never followed: a symlink or other non-regular file at *path* is refused.

    The directory is resolved ONCE (a symlinked parent such as a dotfile-managed ``~/.sift``
    is followed, deliberately) and then pinned by file descriptor; the leaf check, the temp
    file, the rename and the cleanup all go through that descriptor. Swapping the directory
    for a symlink while the write is in progress therefore cannot redirect any step.
    """
    if not _DIR_FD_OK:
        _write_private_by_path(path, text)
        return
    parent = os.path.realpath(path.parent)
    dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    tmp = f".sift-{secrets.token_hex(8)}.tmp"  # fixed length: independent of the target's name
    created = False
    try:
        _after_parent_pinned()
        try:
            st = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise OSError(f"refusing to write through a symlink or non-regular file: {path}")
        # O_EXCL already refuses any existing name, symlinks included; O_NOFOLLOW is belt and braces.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(tmp, flags, _FILE_MODE, dir_fd=dir_fd)
        created = True
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), _FILE_MODE)  # a restrictive umask must not matter; a loose one cannot
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        if created:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=dir_fd)  # production cleanup of our own temp file
        raise
    finally:
        os.close(dir_fd)


def _write_private_by_path(path: Path, text: str) -> None:
    """Path-based variant for platforms without ``dir_fd`` support (same leaf refusal, no pinning)."""
    import tempfile

    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise OSError(f"refusing to write through a symlink or non-regular file: {path}")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".sift-", suffix=".tmp")
    try:
        os.chmod(tmp, _FILE_MODE)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _load_yaml(path: Path) -> dict:
    # No cause is chained anywhere below: parser and decoder messages quote the offending
    # line or byte, which may hold a secret.
    shown = _safe_path(path)
    # Re-checked at use (not redundant with load_config's stat): a FIFO swapped in between would block open().
    _stat_config_file(path, "config file")
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        raise ConfigError(f"config file {shown} is not valid YAML") from None
    except UnicodeDecodeError:
        raise ConfigError(f"config file {shown} is not valid UTF-8 text") from None
    except OSError:
        raise ConfigError(f"config file {shown} cannot be read") from None
    except (ValueError, RecursionError):
        # PyYAML leaks bare ValueError for e.g. an impossible date, RecursionError for deep nesting.
        raise ConfigError(f"config file {shown} is not valid YAML") from None
    # An empty file or a bare `null` means "no settings" (defaults). Any other top level
    # that is not a mapping - including falsy ones such as [] 0 '' false - is an error.
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"config file {shown} must be a mapping of settings at the top level")
    return data


def _validate(data: dict) -> AppConfig:
    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        # pydantic's own message echoes the rejected values; keep only where and why.
        bad = "; ".join(f"{'.'.join(str(p) for p in e['loc'])} ({e['type']})" for e in exc.errors())
        raise ConfigError(f"config has invalid settings: {bad}") from None


def read_credentials(env_file: Path) -> dict[str, Optional[str]]:
    """Parse ~/.sift/.env; {} if absent. Any problem is a value-free ConfigError.

    The single reader of the credentials file: ``load_config`` and ``sift doctor`` both use it,
    so neither can block on a FIFO or leak a decoder message.
    """
    if not _stat_config_file(env_file, "credentials file"):
        return {}
    from dotenv import dotenv_values

    shown = _safe_path(env_file)
    try:
        return dict(dotenv_values(env_file))
    except UnicodeDecodeError:
        raise ConfigError(f"credentials file {shown} is not valid UTF-8 text") from None
    except (OSError, ValueError):
        raise ConfigError(f"credentials file {shown} cannot be read") from None


def _load_credentials_file(env_file: Path) -> None:
    """Load ~/.sift/.env into the environment (the environment wins over the file)."""
    entries = read_credentials(env_file)
    try:
        for key, value in entries.items():
            if value is not None and key not in os.environ:
                os.environ[key] = value
    except (ValueError, OSError):
        # A NUL or an illegal variable name cannot enter the environment; the message names neither.
        raise ConfigError(f"credentials file {_safe_path(env_file)} contains an invalid entry") from None


def load_config(config_path: Optional[Path] = None, *, must_exist: bool = True) -> AppConfig:
    """Load configuration from YAML with env var overrides.

    Priority: CLI flags > env vars > ~/.sift/.env > ~/.sift/config.yaml > defaults.

    An explicit *config_path* that does not exist raises ConfigError (``must_exist=False``
    is for ``sift config``, whose ``--config`` may name a file about to be created; such a
    new file starts from the defaults, never from ``~/.sift/config.yaml``).
    """
    chosen: Optional[Path] = None
    if config_path is not None:
        if _stat_config_file(config_path, "config file"):
            chosen = config_path
        elif must_exist:
            # An explicit --config must never fall back silently to ~/.sift/config.yaml or defaults:
            # a typo would drop the operator's redaction and provider settings without a word.
            raise ConfigError(f"--config file not found: {_safe_path(config_path)}")
    elif _stat_config_file(_APP_DIR / "config.yaml", "config file"):
        chosen = _APP_DIR / "config.yaml"

    # Load credentials from ~/.sift/.env before reading SIFT_LLM_KEY from environment.
    _load_credentials_file(_APP_DIR / ".env")

    config = _resolve_config([chosen], loader=_load_yaml, validator=_validate)

    # Env var overrides (includes values just loaded from ~/.sift/.env)
    llm_key = os.getenv("SIFT_LLM_KEY")
    if llm_key:
        config.summarize.api_key = llm_key

    return config


def default_config_path() -> Path:
    return _APP_DIR / "config.yaml"


def credentials_path() -> Path:
    return _APP_DIR / ".env"


def check_write_target(path: Path) -> bool:
    """Check that the leaf *path* can receive a saved config; True if it will be newly created.

    Raises ConfigError for a symlink (dangling or not), a directory, a FIFO or any other
    non-regular leaf, and for a parent that is not a directory or cannot be searched. It does
    not test write permission: the config is saved before any credential, so a save that
    fails (read-only directory, full disk) leaves no credential behind, and ``_write_private``
    re-checks the leaf under a pinned directory descriptor.
    """
    shown = _safe_path(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    except OSError:
        raise ConfigError(f"cannot write config {shown}") from None
    # lstat does not follow a symlink, so a symlink (even to a regular file) is not S_ISREG.
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"cannot write config {shown}")
    return st is None


def check_credentials_target(path: Path) -> None:
    """Refuse a credentials file that ``_write_private`` would refuse, before the config is saved.

    The leaf must be absent or a regular file; a symlink (dangling or not), directory or FIFO
    raises ConfigError, as does a path that cannot be examined. Same rules as check_write_target.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        raise ConfigError(f"cannot write credentials file {_safe_path(path)}") from None
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"cannot write credentials file {_safe_path(path)}")


def save_config(config: AppConfig, path: Optional[Path] = None) -> Path:
    """Persist config to YAML file (never writes api_key — stored in ~/.sift/.env)."""
    target = path or (_ensure_app_dir() / "config.yaml")
    # Exclude api_key from persisted config — secrets must not be written to disk.
    data = config.model_dump(exclude={"summarize": {"api_key"}})
    _write_private(target, yaml.dump(data, default_flow_style=False))
    return target


def _credential_lines(env_path: Path) -> list[str]:
    """Current lines of ~/.sift/.env; [] if absent. A symlink or non-regular file is refused (OSError).

    A symlinked .env is never read here either, so its target is not even opened.
    """
    try:
        st = os.lstat(env_path)
    except FileNotFoundError:
        return []
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"refusing to use a symlink or non-regular credentials file: {env_path}")
    return env_path.read_text().splitlines()


def save_credentials(api_key: str) -> Path:
    """Store the LLM API key in ~/.sift/.env (mode 600, never in config.yaml)."""
    env_path = _ensure_app_dir() / ".env"
    lines = [line for line in _credential_lines(env_path) if not line.startswith("SIFT_LLM_KEY=")]
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
    lines = [line for line in _credential_lines(env_path) if not line.startswith(f"{env_key}=")]
    lines.append(f"{env_key}={token}")
    _write_private(env_path, "\n".join(lines) + "\n")
    return env_path


def clear_credentials() -> bool:
    """Remove SIFT_LLM_KEY from ~/.sift/.env. Returns True if key was present."""
    env_path = _APP_DIR / ".env"
    lines = _credential_lines(env_path)
    new_lines = [line for line in lines if not line.startswith("SIFT_LLM_KEY=")]
    if len(new_lines) == len(lines):
        return False
    _write_private(env_path, "\n".join(new_lines) + "\n")
    return True
