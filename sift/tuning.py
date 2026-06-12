"""Auto-tuning engine for sift pipeline parameters.

Analyses input characteristics (file sizes, alert count, column count)
and automatically selects optimal chunk_size, drop_raw, streaming mode.

The user never needs to tune these — sift adapts silently.
Explicit CLI flags and config.yaml values always take precedence.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import ClusteringConfig


@dataclass(frozen=True)
class TuneResult:
    """Outcome of auto-tuning — passed into the pipeline."""

    chunk_size: int  # 0 = no chunking
    drop_raw: bool  # True = discard raw dict after normalization
    sub_chunk: bool  # True = sub-file chunking inside streaming reader
    sub_chunk_size: int  # alerts per sub-file batch
    reason: str  # human-readable explanation (shown only in verbose/debug)


# ---------------------------------------------------------------------------
# Thresholds — module-level constants are the canonical defaults.
# They are also reflected in ClusteringConfig fields (same values) so users
# can override them in config.yaml.  auto_tune() reads from cfg when present,
# falling back to these constants when cfg is None — guaranteeing byte-identical
# behaviour at default config.
# ---------------------------------------------------------------------------

_DROP_RAW_BYTES = 500 * 1024 * 1024  # 500 MB — drop raw dict above this
_CHUNK_BYTES = 200 * 1024 * 1024  # 200 MB — enable chunking above this
_SUB_CHUNK_BYTES = 500 * 1024 * 1024  # 500 MB per file — enable sub-file chunking
_DEFAULT_CHUNK_SIZE = 100_000  # alerts per chunk
_DEFAULT_SUB_CHUNK_SIZE = 100_000  # alerts per sub-file batch


def auto_tune(
    total_bytes: int,
    file_count: int,
    largest_file_bytes: int = 0,
    cfg: ClusteringConfig | None = None,
    *,
    user_chunk_size: int | None = None,
    user_drop_raw: bool | None = None,
) -> TuneResult:
    """Determine optimal pipeline parameters based on input characteristics.

    Parameters
    ----------
    total_bytes:
        Sum of all input file sizes.
    file_count:
        Number of input files.
    largest_file_bytes:
        Size of the largest single file (for sub-file chunking decision).
    cfg:
        ClusteringConfig from user config.yaml (provides custom thresholds).
        When supplied, the new ``drop_raw_threshold_mb``, ``chunk_threshold_mb``,
        and ``default_chunk_size`` fields override the module-level constants.
    user_chunk_size:
        Explicit --chunk-size from CLI (None = not set by user).
    user_drop_raw:
        Explicit --drop-raw from CLI (None = not set by user).

    Returns
    -------
    TuneResult with optimal parameters. Explicit user values always win.
    """
    reasons: list[str] = []

    # Resolve effective thresholds: cfg fields > module constants
    _mb = 1024 * 1024
    drop_raw_bytes = (cfg.drop_raw_threshold_mb * _mb) if cfg else _DROP_RAW_BYTES
    chunk_bytes = (cfg.chunk_threshold_mb * _mb) if cfg else _CHUNK_BYTES
    default_chunk_sz = cfg.default_chunk_size if cfg else _DEFAULT_CHUNK_SIZE

    # --- Drop raw ---
    if user_drop_raw is not None:
        drop_raw = user_drop_raw
        if user_drop_raw:
            reasons.append("--drop-raw set by user")
    elif total_bytes > drop_raw_bytes:
        drop_raw = True
        drop_mb = drop_raw_bytes // _mb
        reasons.append(f"auto drop-raw: input {total_bytes / (1024**3):.1f} GB > {drop_mb} MB threshold")
    else:
        drop_raw = False

    # --- Chunk size ---
    cfg_chunk = cfg.chunk_size if cfg else 0
    if user_chunk_size is not None and user_chunk_size > 0:
        chunk_size = user_chunk_size
        reasons.append(f"--chunk-size {chunk_size} set by user")
    elif cfg_chunk > 0:
        chunk_size = cfg_chunk
        reasons.append(f"chunk_size {chunk_size} from config.yaml")
    elif total_bytes > chunk_bytes:
        chunk_size = default_chunk_sz
        chunk_mb = chunk_bytes // _mb
        reasons.append(f"auto chunk-size: input {total_bytes / (1024**3):.1f} GB > {chunk_mb} MB threshold")
    else:
        chunk_size = 0

    # --- Sub-file chunking ---
    sub_threshold = (cfg.sub_chunk_threshold_mb * _mb) if cfg else _SUB_CHUNK_BYTES
    sub_size = cfg.sub_chunk_size if cfg else _DEFAULT_SUB_CHUNK_SIZE
    if largest_file_bytes > sub_threshold:
        sub_chunk = True
        reasons.append(
            f"auto sub-chunk: largest file {largest_file_bytes / (1024**3):.1f} GB "
            f"> {sub_threshold / (1024**3):.1f} GB threshold"
        )
    else:
        sub_chunk = False

    reason = "; ".join(reasons) if reasons else "no tuning needed (small input)"

    return TuneResult(
        chunk_size=chunk_size,
        drop_raw=drop_raw,
        sub_chunk=sub_chunk,
        sub_chunk_size=sub_size,
        reason=reason,
    )
