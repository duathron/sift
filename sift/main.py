"""sift — AI-Powered Alert Triage Summarizer.

Entry point for the Typer CLI. Wires together:
  normalizers → dedup → ioc_extract → cluster → prioritize → summarize → output
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from . import __version__
from .banner import show_banner
from .config import load_config
from .models import PipelineManifest, TriageReport

app = typer.Typer(
    name="sift",
    help="AI-powered alert triage summarizer for SOC teams.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Format enum
# ---------------------------------------------------------------------------

class OutputFormat(str):
    RICH = "rich"
    CONSOLE = "console"
    JSON = "json"
    CSV = "csv"
    STIX = "stix"


# ---------------------------------------------------------------------------
# Helper: resolve normalizer
# ---------------------------------------------------------------------------

def _normalize(raw: str) -> tuple[list, str]:
    """Auto-detect format and return (alerts, format_name)."""
    from .normalizers.csv_normalizer import CSVNormalizer
    from .normalizers.generic import GenericNormalizer
    from .normalizers.splunk import SplunkNormalizer

    for normalizer in [SplunkNormalizer(), GenericNormalizer(), CSVNormalizer()]:
        if normalizer.can_handle(raw):
            alerts = normalizer.normalize(raw)
            if alerts:
                return alerts, normalizer.name
    # Last resort: generic without can_handle check
    alerts = GenericNormalizer().normalize(raw)
    return alerts, "generic"


# ---------------------------------------------------------------------------
# Helper: build summarizer
# ---------------------------------------------------------------------------

def _build_summarizer(provider: str, config):
    from .summarizers.template import TemplateSummarizer

    # Attach injection whitelist patterns so build_cluster_prompt() can use them.
    # This bridges PromptInjectionConfig → SummarizeConfig without changing the schema.
    summarize_cfg = config.summarize
    summarize_cfg._injection_whitelist = config.injection.whitelist_patterns

    if provider == "template":
        return TemplateSummarizer()

    if provider == "mock":
        from .summarizers.mock import MockSummarizer
        return MockSummarizer()

    if provider == "anthropic":
        try:
            from .summarizers.anthropic import AnthropicSummarizer
            return AnthropicSummarizer(config.summarize)
        except ImportError as e:
            console.print(f"[yellow]Warning:[/yellow] {e}")
            console.print("[dim]Falling back to template summarizer.[/dim]")
            return TemplateSummarizer()

    if provider == "openai":
        try:
            from .summarizers.openai import OpenAISummarizer
            return OpenAISummarizer(config.summarize)
        except ImportError as e:
            console.print(f"[yellow]Warning:[/yellow] {e}")
            console.print("[dim]Falling back to template summarizer.[/dim]")
            return TemplateSummarizer()

    if provider == "ollama":
        from .summarizers.ollama import OllamaSummarizer
        return OllamaSummarizer(config.summarize)

    console.print(f"[yellow]Unknown provider '{provider}', using template.[/yellow]")
    return TemplateSummarizer()


# ---------------------------------------------------------------------------
# Helper: enrichment consent
# ---------------------------------------------------------------------------

def _check_enrich_consent(yes: bool, cfg) -> bool:
    """Returns True if consent is given for external API calls."""
    if yes or cfg.enrich.consent_given:
        return True
    console.print(
        "\n[yellow]--enrich[/yellow] will call external APIs (barb, vex).\n"
        "This sends IOC data to VirusTotal (via vex) and runs local barb analysis.\n"
    )
    return typer.confirm("Proceed with enrichment?", default=False)


# ---------------------------------------------------------------------------
# Shared constants + path resolver
# ---------------------------------------------------------------------------

_SUPPORTED_SUFFIXES = {".json", ".csv", ".ndjson", ".log"}


def _resolve_paths(raw_paths: list[Path]) -> list[Path]:
    """Expand dirs and validate files; raise typer.Exit(2) on missing paths."""
    resolved: list[Path] = []
    for p in raw_paths:
        if str(p) == "-":
            resolved.append(p)
        elif p.is_dir():
            found = sorted(
                f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in _SUPPORTED_SUFFIXES
            )
            if not found:
                console.print(f"[yellow]Warning:[/yellow] No supported files found in directory: {p}")
            else:
                resolved.extend(found)
        elif p.exists():
            resolved.append(p)
        else:
            console.print(f"[red]Error:[/red] File not found: {p}")
            raise typer.Exit(2)
    return resolved


# ---------------------------------------------------------------------------
# Helper: triage --help status panel + callbacks
# ---------------------------------------------------------------------------

def _print_triage_config_panel(
    *,
    resolved_paths: "list[Path]",
    total_bytes: int,
    summarize: bool,
    provider: str,
    model: "Optional[str]",
    enrich_active: bool,
    enrich_mode_str: str,
    redact: "Optional[str]",
    cache_enabled: bool,
    chunk_size: int,
    no_dedup: bool,
    time_window: int,
) -> None:
    """Print a ffuf-style config summary panel before the triage pipeline starts."""
    from rich.filesize import decimal as _fmt_size
    from rich.panel import Panel
    from rich.text import Text

    _LBL = 10    # fixed label column width → values always start at the same offset

    def row(label: str, value: str) -> str:
        return f"{label:<{_LBL}}{value}\n"

    # --- Input ---
    file_count = len(resolved_paths)
    stdin_count = sum(1 for p in resolved_paths if str(p) == "-")
    named_count = file_count - stdin_count
    size_str = _fmt_size(total_bytes) if total_bytes > 0 else "?"
    input_val = (
        f"{file_count} file{'s' if file_count != 1 else ''} ({size_str})"
        if not stdin_count else
        f"stdin" if named_count == 0 else
        f"{named_count} file{'s' if named_count != 1 else ''} + stdin ({size_str})"
    )

    # --- Summarize ---
    if summarize:
        model_hint = f" [dim]({model or 'auto'})[/dim]" if provider not in ("template", "mock") else ""
        sum_val = f"[green]on[/green]  {provider}{model_hint}"
    else:
        sum_val = "[dim]off[/dim]"

    # --- Enrich ---
    enrich_val = f"[green]on[/green]  {enrich_mode_str}" if enrich_active else "[dim]off[/dim]"

    # --- Redact ---
    redact_val = redact if redact else "[dim](none)[/dim]"

    # --- Cache ---
    cache_val = "[green]on[/green]" if cache_enabled else "[dim]off[/dim]"

    # --- Chunks ---
    if chunk_size > 0:
        chunk_val = f"[dim]auto[/dim] ({chunk_size:,} alerts/chunk)"
    else:
        chunk_val = "[dim]off[/dim] (small input)"

    # --- Dedup ---
    dedup_val = "[dim]off[/dim]  [yellow](--no-dedup)[/yellow]" if no_dedup else f"[green]on[/green]  [dim]({time_window} min window)[/dim]"

    body = Text.from_markup(
        row("Input", input_val)
        + row("Summarize", sum_val)
        + row("Enrich", enrich_val)
        + row("Redact", redact_val)
        + row("Cache", cache_val)
        + row("Chunks", chunk_val)
        + row("Dedup", dedup_val).rstrip("\n")
    )

    from rich.console import Console as _RichConsole
    _RichConsole(stderr=True).print(
        Panel(body, title="[bold]Triage Config[/bold]", expand=False, padding=(0, 2))
    )


def _print_triage_setup_status() -> None:
    """Print a dynamic config-status panel below --help output."""
    try:
        from rich.console import Console as _Console
        from rich.panel import Panel
        from rich.text import Text
        _c = _Console()
        cfg = load_config()

        key = cfg.summarize.api_key or ""
        key_line = f"[green]✓[/green] set (via ~/.sift/.env)" if key else "[yellow]✗[/yellow] not set  (run: sift config --api-key <key>)"
        provider_line = cfg.summarize.provider
        cache_line = "on  [dim](--no-cache to disable)[/dim]" if cfg.cache_enabled else "off [dim](default)[/dim]"
        redact_fields = cfg.redaction.fields if hasattr(cfg, "redaction") else []
        redact_line = ", ".join(redact_fields) if redact_fields else "[dim](none)[/dim]"

        body = Text.from_markup(
            f"  API key    {key_line}\n"
            f"  Provider   {provider_line}\n"
            f"  Cache      {cache_line}\n"
            f"  Redact     {redact_line}\n\n"
            f"  [dim]Run 'sift config --show' for full configuration.[/dim]"
        )
        _c.print(Panel(body, title="[bold]Current Setup[/bold]", expand=False))
    except Exception:
        pass


def _triage_help_callback(ctx: "typer.Context", param: "typer.CallbackParam", value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    import click
    click.echo(ctx.get_help())
    _print_triage_setup_status()
    raise typer.Exit()


def _help_all_callback(ctx: "typer.Context", param: "typer.CallbackParam", value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    for p in ctx.command.params:
        p.hidden = False
    import click
    click.echo(ctx.get_help())
    _print_triage_setup_status()
    raise typer.Exit()


# ---------------------------------------------------------------------------
# triage command
# ---------------------------------------------------------------------------

@app.command(context_settings={"help_option_names": []})
def triage(
    files: Annotated[list[Path], typer.Argument(
        help=(
            "Alert files or directories to triage (JSON, Splunk JSON, CSV). "
            "Pass multiple paths to correlate alerts across sources. "
            "Use '-' for stdin. Directories are scanned for .json and .csv files."
        ),
        show_default=False,
    )],
    # --- Output ---
    format: Annotated[str, typer.Option(
        "--format", "-f",
        help="Output format: rich | console | json | csv | stix",
        rich_help_panel="Output",
    )] = "rich",
    output: Annotated[Optional[Path], typer.Option(
        "--output", "-o",
        help="Save output to file.",
        rich_help_panel="Output",
    )] = None,
    quiet: Annotated[bool, typer.Option(
        "--quiet", "-q",
        help="Suppress banner and status lines.",
        rich_help_panel="Output",
    )] = False,
    # --- AI Summarization ---
    summarize: Annotated[bool, typer.Option(
        "--summarize", "-s",
        help="Generate AI summary. Uses --provider (template requires no key).",
        rich_help_panel="AI Summarization",
    )] = False,
    provider: Annotated[Optional[str], typer.Option(
        "--provider",
        help="LLM provider: template (no key) | anthropic | openai | ollama",
        rich_help_panel="AI Summarization",
    )] = None,
    # --- IOC Enrichment ---
    enrich: Annotated[Optional[str], typer.Option(
        "--enrich",
        help="Enrich IOCs: local (no API) | barb | vex | all (external, requires consent).",
        rich_help_panel="IOC Enrichment",
    )] = None,
    yes: Annotated[bool, typer.Option(
        "--yes", "-y",
        help="Skip consent prompt for external enrichment API calls.",
        rich_help_panel="IOC Enrichment",
    )] = False,
    # --- Privacy ---
    redact_fields: Annotated[Optional[str], typer.Option(
        "--redact-fields",
        help="Fields to redact before AI submission (e.g. 'user,host,source_ip').",
        rich_help_panel="Privacy",
    )] = None,
    # --- Options ---
    filter: Annotated[Optional[str], typer.Option(
        "--filter",
        help="Filter clusters (e.g. 'priority >= HIGH').",
    )] = None,
    no_cache: Annotated[bool, typer.Option(
        "--no-cache",
        help="Disable result caching for this run.",
    )] = False,
    # --- Help ---
    help_flag: Annotated[Optional[bool], typer.Option(
        "--help", "-h",
        help="Show this message and exit.",
        is_eager=True,
        callback=_triage_help_callback,
        expose_value=False,
    )] = None,
    help_all: Annotated[Optional[bool], typer.Option(
        "--help-all",
        help="Show all options including expert flags.",
        is_eager=True,
        callback=_help_all_callback,
        expose_value=False,
    )] = None,
    # --- Expert / hidden flags (sift triage --help-all to reveal) ---
    config_path: Annotated[Optional[Path], typer.Option(
        "--config",
        help="Path to a custom config.yaml (default: ~/.sift/config.yaml).",
        show_default=False,
        hidden=True,
    )] = None,
    no_dedup: Annotated[bool, typer.Option(
        "--no-dedup",
        help="Skip alert deduplication. Use only for testing or when your SIEM already deduplicates.",
        hidden=True,
    )] = False,
    validate_only: Annotated[bool, typer.Option(
        "--validate-only",
        help="[Deprecated] Use 'sift validate <file>' instead. Parse and validate without producing output.",
        hidden=True,
    )] = False,
    chunk_size: Annotated[int, typer.Option(
        "--chunk-size",
        help="Override auto-tuned chunk size for clustering (0 = auto). Use when auto-tuning picks wrong size.",
        hidden=True,
    )] = 0,
    drop_raw: Annotated[bool, typer.Option(
        "--drop-raw",
        help="Discard raw alert data after normalization — halves RAM for wide CSVs. Auto-enabled for files >500 MB.",
        hidden=True,
    )] = False,
    enrich_mode: Annotated[Optional[str], typer.Option(
        "--enrich-mode",
        help="[Deprecated] Use --enrich MODE instead (e.g. --enrich local).",
        hidden=True,
    )] = None,
) -> None:
    """Triage alerts from one or more FILES or directories.

    Multiple sources are merged before clustering, enabling cross-source correlation.
    """

    # --- Load config ---
    cfg = load_config(config_path)

    # --- Resolve effective redact fields (CLI flag overrides config default) ---
    _effective_redact: Optional[str] = redact_fields or (
        ",".join(cfg.redaction.fields) if cfg.redaction.fields else None
    )

    # --- Backward compat: --enrich-mode (deprecated) merged into --enrich ---
    if enrich_mode and enrich is None:
        console.print(
            "[yellow]Note:[/yellow] --enrich-mode is deprecated. Use --enrich MODE instead "
            "(e.g. --enrich local)."
        )
        enrich = enrich_mode

    # --- Resolve effective enrich mode ---
    _enrich_active = enrich is not None
    _enrich_mode_str = (enrich or "all").lower()

    # --- Banner ---
    show_banner(
        quiet=quiet or cfg.output.quiet,
        update_check_enabled=cfg.update_check.enabled,
        check_interval_hours=cfg.update_check.check_interval_hours,
    )

    # --- Resolve input paths (expand directories, validate files) ---
    _LARGE_FILE_THRESHOLD_BYTES = 50 * 1024 * 1024   # 50 MB
    _STREAM_BATCH_LINES = 5_000                        # normalize this many lines at a time

    def _stream_alerts(path: Path, hasher, show_progress: bool, *, sub_chunk: bool = False) -> tuple[list, str]:
        """Read a large file line-by-line in batches with optional progress bar.

        Avoids loading the entire file into RAM — critical for multi-GB logs.
        Tracks bytes read for accurate %, elapsed time, and ETA via rich.progress.

        When *sub_chunk* is True, processes alerts in batches of ``sub_chunk_size``
        through the full mini-pipeline (dedup → IOC → cluster → prioritize) and
        returns a list of :class:`TriageReport` objects (stored in ``all_source_alerts``).
        This bounds peak RAM to ~200MB per batch even for multi-GB files.
        When *sub_chunk* is False, returns the raw Alert list as before.
        """
        from rich.progress import (
            BarColumn,
            FileSizeColumn,
            Progress,
            TaskProgressColumn,
            TextColumn,
            TimeElapsedColumn,
            TimeRemainingColumn,
            TotalFileSizeColumn,
            TransferSpeedColumn,
        )

        _sub_chunk_size = cfg.clustering.sub_chunk_size  # default 100_000

        file_size = path.stat().st_size
        all_source_alerts: list = []   # Alert list (sub_chunk=False) or TriageReport list (sub_chunk=True)
        _pending_alerts: list = []     # buffer for sub-chunk accumulation
        detected_fmt = "generic"
        buffer: list[str] = []
        _csv_header: str | None = None  # preserved CSV header for subsequent batches

        def _process_sub_chunk() -> None:
            """Run mini-pipeline on accumulated alerts, emit TriageReport, free Alert objects."""
            nonlocal _pending_alerts
            if not _pending_alerts:
                return
            from .pipeline.dedup import DeduplicatorConfig, deduplicate
            from .pipeline.ioc_extractor import enrich_alerts_iocs
            _dedup_cfg = DeduplicatorConfig(time_window_minutes=cfg.clustering.time_window_minutes)
            _deduped, _ = deduplicate(_pending_alerts, _dedup_cfg)
            if _effective_redact:
                _fields = [f.strip() for f in _effective_redact.split(",") if f.strip()]
                _deduped = [a.redact(_fields) for a in _deduped]
            if drop_raw:
                _deduped = [a.model_copy(update={"raw": {}}) for a in _deduped]
            _deduped = enrich_alerts_iocs(_deduped)
            _cls = cluster_alerts(_deduped, cfg.clustering)
            _cls = prioritize_all(_cls, cfg.scoring)
            all_source_alerts.append(TriageReport(
                input_file=str(path),
                alerts_ingested=len(_pending_alerts),
                alerts_after_dedup=len(_deduped),
                clusters=_cls,
                analyzed_at=datetime.now(tz=timezone.utc),
            ))
            _pending_alerts = []

        def _flush_buffer() -> None:
            nonlocal detected_fmt, _csv_header
            if not buffer:
                return
            try:
                raw_batch = "\n".join(buffer)
                # CSV header fix: after the first batch, prepend the saved header
                # so that csv.DictReader can map columns correctly in every batch.
                if _csv_header is not None and detected_fmt == "csv":
                    raw_batch = _csv_header + "\n" + raw_batch
                batch_alerts, fmt = _normalize(raw_batch)
                if batch_alerts:
                    # Save CSV header from first successful parse for subsequent batches
                    if _csv_header is None and fmt == "csv" and buffer:
                        _csv_header = buffer[0]
                    if drop_raw and not sub_chunk:
                        batch_alerts = [a.model_copy(update={"raw": {}}) for a in batch_alerts]
                    if sub_chunk:
                        _pending_alerts.extend(batch_alerts)
                        if len(_pending_alerts) >= _sub_chunk_size:
                            _process_sub_chunk()
                    else:
                        all_source_alerts.extend(batch_alerts)
                    detected_fmt = fmt
            except Exception:
                pass
            buffer.clear()

        progress_ctx = (
            Progress(
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=None),
                TaskProgressColumn(),
                TextColumn("•"),
                FileSizeColumn(),
                TextColumn("/"),
                TotalFileSizeColumn(),
                TextColumn("•"),
                TransferSpeedColumn(),
                TextColumn("•"),
                TimeElapsedColumn(),
                TextColumn("ETA"),
                TimeRemainingColumn(),
                console=Console(stderr=True),
                transient=False,
                refresh_per_second=10,
            )
            if show_progress
            else None
        )

        def _run(progress, task_id) -> None:
            bytes_read = 0
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line_bytes = line.encode("utf-8", errors="replace")
                    bytes_read += len(line_bytes)
                    hasher.update(line_bytes)
                    stripped = line.rstrip("\n")
                    if stripped:
                        buffer.append(stripped)
                    if len(buffer) >= _STREAM_BATCH_LINES:
                        _flush_buffer()
                        if progress is not None:
                            progress.update(task_id, completed=bytes_read)
            _flush_buffer()
            if sub_chunk:
                _process_sub_chunk()  # flush remaining alerts
            if progress is not None:
                progress.update(task_id, completed=file_size)

        if progress_ctx is not None:
            with progress_ctx as progress:
                desc = f"Reading {path.name}" + (" (sub-chunked)" if sub_chunk else "")
                task_id = progress.add_task(desc, total=file_size)
                _run(progress, task_id)
        else:
            _run(None, None)

        return all_source_alerts, detected_fmt

    resolved_paths = _resolve_paths(files)
    if not resolved_paths:
        console.print("[red]Error:[/red] No input files to process.")
        raise typer.Exit(2)

    # --- Early validation ---
    if chunk_size < 0:
        console.print("[red]Error:[/red] --chunk-size must be 0 (auto) or a positive integer.")
        raise typer.Exit(2)

    _quiet_mode = quiet or cfg.output.quiet
    _PROGRESS_THRESHOLD = 10_000

    import hashlib as _hashlib

    from .pipeline.chunker import chunk_alerts, merge_triage_reports
    from .pipeline.clusterer import cluster_alerts
    from .pipeline.prioritizer import prioritize_all
    from rich.progress import (
        BarColumn, MofNCompleteColumn, Progress as _Progress,
        SpinnerColumn, TaskProgressColumn, TextColumn as _TextColumn,
        TimeElapsedColumn, TimeRemainingColumn,
    )
    from rich.status import Status as _Status

    # --- Auto-tuning: compute total + largest file sizes for tuning engine ---
    from .tuning import auto_tune
    _total_bytes_estimate = sum(
        p.stat().st_size for p in resolved_paths if str(p) != "-" and p.exists()
    )
    _largest_file_estimate = max(
        (p.stat().st_size for p in resolved_paths if str(p) != "-" and p.exists()),
        default=0,
    )
    _tune = auto_tune(
        total_bytes=_total_bytes_estimate,
        file_count=len(resolved_paths),
        largest_file_bytes=_largest_file_estimate,
        cfg=cfg.clustering,
        user_chunk_size=chunk_size if chunk_size > 0 else None,
        user_drop_raw=True if drop_raw else None,
    )

    # Effective values: auto-tune wins unless user explicitly set the flag
    effective_chunk_size = _tune.chunk_size
    drop_raw = _tune.drop_raw  # may be upgraded by auto-tune for large files

    if not _quiet_mode and _tune.reason != "no tuning needed (small input)":
        console.print(f"[dim]Auto-tuned: {_tune.reason}[/dim]")

    # --- Triage config panel (ffuf-style, shown before pipeline starts) ---
    if not _quiet_mode:
        _print_triage_config_panel(
            resolved_paths=resolved_paths,
            total_bytes=_total_bytes_estimate,
            summarize=summarize,
            provider=provider or cfg.summarize.provider,
            model=cfg.summarize.model,
            enrich_active=_enrich_active,
            enrich_mode_str=_enrich_mode_str,
            redact=_effective_redact,
            cache_enabled=not no_cache and cfg.cache_enabled,
            chunk_size=effective_chunk_size,
            no_dedup=no_dedup,
            time_window=cfg.clustering.time_window_minutes,
        )

    # --- Cache (default on, --no-cache to disable) ---
    _cache_enabled = not no_cache and cfg.cache_enabled

    # --- Cache: fingerprint pre-pass (streams bytes only, no Alert objects) ---
    # When cache is active we fingerprint all files first for a cache lookup
    # before kicking off the expensive per-file pipeline.
    _alert_cache = None
    _cache_key: str | None = None
    _stdin_raw: str | None = None  # stdin content captured during fingerprint pass

    if _cache_enabled:
        _fp_hasher = _hashlib.sha256()
        for _fp_path in resolved_paths:
            if str(_fp_path) == "-":
                _stdin_raw = sys.stdin.read()
                _fp_hasher.update(_stdin_raw.encode("utf-8", errors="replace"))
            else:
                _fp_size = _fp_path.stat().st_size
                if _fp_size > 0:
                    try:
                        with open(_fp_path, "rb") as _fh:
                            for _blk in iter(lambda: _fh.read(65536), b""):
                                _fp_hasher.update(_blk)
                    except Exception as _exc:
                        console.print(f"[red]Error fingerprinting {_fp_path}:[/red] {_exc}")
                        raise typer.Exit(2)

        from .cache import AlertCache, CacheConfig
        _cache_key = _fp_hasher.hexdigest()
        _alert_cache = AlertCache(CacheConfig(enabled=True))
        _cached = _alert_cache.get(_cache_key)
        if _cached is not None:
            if not _quiet_mode:
                console.print(f"[dim]Cache hit ({_cache_key[:12]}…) — skipping pipeline.[/dim]")
            _render_output(_cached, format=format, output_path=output, cfg=cfg, quiet=quiet)
            raise typer.Exit(0)
        if not _quiet_mode:
            console.print(f"[dim]Cache miss ({_cache_key[:12]}…) — running pipeline.[/dim]")

    # --- Per-file pipeline ---
    # Architecture: each file is processed independently to bound peak RAM.
    #
    # Small files (< 50MB): read_text → normalize → full Alert list.
    # Medium files (50MB – sub_chunk_threshold): streaming read → full Alert list.
    # Large files (> sub_chunk_threshold): streaming read with sub-file chunking —
    #   processes N alerts at a time (dedup → IOC → cluster → TriageReport), then
    #   frees Alert objects before the next batch. Peak RAM ≈ 200–300 MB per batch.
    #
    # After each file: Alert objects are freed. Only compact TriageReport objects
    # (containing Cluster objects, not raw Alert data) accumulate across files.
    #
    # Cross-source IOC correlation is restored by merge_triage_reports() at the end,
    # which uses Union-Find IOC-overlap re-merge across all chunks and files.

    _sub_chunk_threshold = cfg.clustering.sub_chunk_threshold_mb * 1024 * 1024

    file_reports: list[TriageReport] = []
    total_ingested = 0
    total_after_dedup = 0
    source_labels: list[str] = []
    detected_formats: list[str] = []
    _total_bytes = 0  # track total input size for large-data warning

    for path in resolved_paths:
        label = str(path)
        _is_sub_chunked = False  # did _stream_alerts handle the full pipeline internally?
        try:
            if str(path) == "-":
                raw = _stdin_raw if _stdin_raw is not None else sys.stdin.read()
                _stdin_raw = None
                label = "<stdin>"
                if not raw.strip():
                    console.print("[yellow]Warning:[/yellow] Skipping empty stdin.")
                    continue
                source_alerts, fmt = _normalize(raw)
                if drop_raw:
                    source_alerts = [a.model_copy(update={"raw": {}}) for a in source_alerts]
                del raw
            else:
                file_size = path.stat().st_size
                _total_bytes += file_size
                if file_size == 0:
                    console.print(f"[yellow]Warning:[/yellow] Skipping empty file: {label}")
                    continue
                _no_op_hasher = _hashlib.sha256()
                _hash_target = _no_op_hasher if _cache_enabled else _hashlib.sha256()

                if file_size > _sub_chunk_threshold:
                    # Large file: sub-file chunking — _stream_alerts runs the full
                    # mini-pipeline (dedup → IOC → cluster) per batch internally.
                    # Returns a list of TriageReport objects, NOT Alert objects.
                    if not _quiet_mode:
                        _size_gb = file_size / (1024 ** 3)
                        console.print(
                            f"[dim]  {path.name} ({_size_gb:.1f} GB) — sub-file chunking "
                            f"(batches of {cfg.clustering.sub_chunk_size:,} alerts)[/dim]"
                        )
                    sub_reports, fmt = _stream_alerts(path, _hash_target, not _quiet_mode, sub_chunk=True)
                    if sub_reports:
                        source_labels.append(label)
                        detected_formats.append(fmt)
                        file_report = merge_triage_reports(sub_reports)
                        total_ingested += file_report.alerts_ingested
                        total_after_dedup += file_report.alerts_after_dedup
                        file_reports.append(file_report)
                        del sub_reports
                    else:
                        console.print(f"[yellow]Warning:[/yellow] No alerts parsed from: {label}")
                    continue  # skip the normal pipeline below — already handled
                elif file_size > _LARGE_FILE_THRESHOLD_BYTES:
                    source_alerts, fmt = _stream_alerts(path, _hash_target, not _quiet_mode)
                    if drop_raw:
                        source_alerts = [a.model_copy(update={"raw": {}}) for a in source_alerts]
                else:
                    raw = path.read_text(encoding="utf-8")
                    source_alerts, fmt = _normalize(raw)
                    if drop_raw:
                        source_alerts = [a.model_copy(update={"raw": {}}) for a in source_alerts]
                    del raw
        except typer.Exit:
            raise
        except Exception as exc:
            console.print(f"[red]Error reading {label}:[/red] {exc}")
            raise typer.Exit(2)

        if not source_alerts:
            console.print(f"[yellow]Warning:[/yellow] No alerts parsed from: {label}")
            continue

        source_labels.append(label)
        detected_formats.append(fmt)

        # F-10: filter phantom alerts
        source_alerts = [
            a for a in source_alerts
            if a.title not in ("Unknown Alert", "Unknown", "")
            or a.description or a.source_ip or a.dest_ip
            or a.user or a.host or a.iocs or a.raw
        ]
        if not source_alerts:
            console.print(f"[yellow]Warning:[/yellow] All alerts from {label} were empty/phantom.")
            source_labels.pop()
            detected_formats.pop()
            continue

        file_ingested = len(source_alerts)
        total_ingested += file_ingested

        # --- Dedup (per file) ---
        if no_dedup:
            alerts_for_clustering = source_alerts
            file_dedup_count = file_ingested
        else:
            from .pipeline.dedup import DeduplicatorConfig, deduplicate
            _dedup_cfg = DeduplicatorConfig(time_window_minutes=cfg.clustering.time_window_minutes)
            if file_ingested >= _PROGRESS_THRESHOLD and not _quiet_mode:
                with _Status(
                    f"[bold]Deduplicating {file_ingested:,} alerts from {path.name}…[/bold]",
                    console=Console(stderr=True),
                    spinner="dots",
                ):
                    alerts_for_clustering, dedup_stats = deduplicate(source_alerts, _dedup_cfg)
            else:
                alerts_for_clustering, dedup_stats = deduplicate(source_alerts, _dedup_cfg)
            file_dedup_count = dedup_stats.deduplicated_count
            if not _quiet_mode:
                console.print(
                    f"[dim]  {path.name}: {file_ingested:,} → {file_dedup_count:,} alerts "
                    f"({dedup_stats.removed_count:,} duplicates removed)[/dim]"
                )

        del source_alerts
        total_after_dedup += file_dedup_count

        # --- Field-level redaction (optional) ---
        if _effective_redact:
            fields_to_redact = [f.strip() for f in _effective_redact.split(",") if f.strip()]
            try:
                alerts_for_clustering = [a.redact(fields_to_redact) for a in alerts_for_clustering]
            except ValueError as exc:
                console.print(f"[red]Error:[/red] {exc}")
                raise typer.Exit(2)

        # --- IOC extraction ---
        from .pipeline.ioc_extractor import enrich_alerts_iocs
        alerts_for_clustering = enrich_alerts_iocs(alerts_for_clustering)

        # --- Cluster + Prioritize ---
        if effective_chunk_size > 0:
            chunks = chunk_alerts(alerts_for_clustering, effective_chunk_size)
            n_chunks = len(chunks)
            _chunk_reports: list[TriageReport] = []

            if n_chunks > 1 and not _quiet_mode:
                with _Progress(
                    SpinnerColumn(),
                    _TextColumn("[bold]{task.description}"),
                    BarColumn(bar_width=None),
                    MofNCompleteColumn(),
                    TaskProgressColumn(),
                    _TextColumn("•"),
                    TimeElapsedColumn(),
                    _TextColumn("ETA"),
                    TimeRemainingColumn(),
                    console=Console(stderr=True),
                    transient=False,
                    refresh_per_second=10,
                ) as prog:
                    task = prog.add_task(
                        f"Clustering {file_dedup_count:,} alerts [{path.name}] in {n_chunks} chunks",
                        total=n_chunks,
                    )
                    for _chk in chunks:
                        _cls = cluster_alerts(_chk, cfg.clustering)
                        _cls = prioritize_all(_cls, cfg.scoring)
                        _chunk_reports.append(TriageReport(
                            input_file=label,
                            alerts_ingested=len(_chk),
                            alerts_after_dedup=len(_chk),
                            clusters=_cls,
                            analyzed_at=datetime.now(tz=timezone.utc),
                        ))
                        prog.advance(task)
            else:
                for _chk in chunks:
                    _cls = cluster_alerts(_chk, cfg.clustering)
                    _cls = prioritize_all(_cls, cfg.scoring)
                    _chunk_reports.append(TriageReport(
                        input_file=label,
                        alerts_ingested=len(_chk),
                        alerts_after_dedup=len(_chk),
                        clusters=_cls,
                        analyzed_at=datetime.now(tz=timezone.utc),
                    ))
            file_report = merge_triage_reports(_chunk_reports)
        else:
            if file_dedup_count >= _PROGRESS_THRESHOLD and not _quiet_mode:
                with _Status(
                    f"[bold]Clustering {file_dedup_count:,} alerts from {path.name}…[/bold]",
                    console=Console(stderr=True),
                    spinner="dots",
                ):
                    _cls = cluster_alerts(alerts_for_clustering, cfg.clustering)
                    _cls = prioritize_all(_cls, cfg.scoring)
            else:
                _cls = cluster_alerts(alerts_for_clustering, cfg.clustering)
                _cls = prioritize_all(_cls, cfg.scoring)

            file_report = TriageReport(
                input_file=label,
                alerts_ingested=file_ingested,
                alerts_after_dedup=file_dedup_count,
                clusters=_cls,
                analyzed_at=datetime.now(tz=timezone.utc),
            )

        del alerts_for_clustering
        file_reports.append(file_report)

    if not file_reports:
        console.print("[yellow]Warning:[/yellow] No alerts could be parsed from any input source.")
        raise typer.Exit(0)

    input_file_str = ", ".join(source_labels) if len(source_labels) > 1 else (source_labels[0] if source_labels else "<unknown>")

    if len(source_labels) > 1 and not _quiet_mode:
        console.print(
            f"[dim]Sources: {len(source_labels)} files — "
            f"{total_ingested:,} alerts ingested, {total_after_dedup:,} after dedup — "
            f"merging for cross-source IOC correlation.[/dim]"
        )

    # --- Merge per-file reports (IOC-overlap Union-Find restores cross-source clustering) ---
    merged = merge_triage_reports(file_reports)
    del file_reports
    clusters = merged.clusters

    # --- Enrichment (optional) ---
    enrichment = None
    if _enrich_active:
        from .enrichers.runner import EnrichmentMode, EnrichmentRunner
        mode_map = {"barb": EnrichmentMode.BARB, "vex": EnrichmentMode.VEX, "all": EnrichmentMode.ALL, "local": EnrichmentMode.LOCAL}
        eff_mode = mode_map.get(_enrich_mode_str, EnrichmentMode.ALL)
        # LOCAL mode skips consent prompt — no data leaves the system
        consent = (eff_mode is EnrichmentMode.LOCAL) or _check_enrich_consent(yes, cfg)
        if consent:
            runner = EnrichmentRunner(mode=eff_mode)
            all_iocs = runner.collect_iocs_from_report(
                type("R", (), {"clusters": clusters})()
            )
            if all_iocs:
                if not _quiet_mode:
                    console.print(f"  [dim]Enriching {len(all_iocs)} IOC(s) via {eff_mode.value}...[/dim]")
                try:
                    max_ioc_limit = getattr(cfg.enrich, 'max_iocs', 20)
                    enrichment = runner.enrich(all_iocs, max_iocs=max_ioc_limit)
                except Exception as e:
                    console.print(f"[yellow]Warning:[/yellow] Enrichment failed: {e}")
        else:
            console.print("[dim]Enrichment skipped.[/dim]")

    # --- Build report ---
    report = TriageReport(
        input_file=input_file_str,
        alerts_ingested=total_ingested,
        alerts_after_dedup=total_after_dedup,
        clusters=clusters,
        enrichment=enrichment,
        manifest=PipelineManifest(
            sift_version=__version__,
            input_format=detected_formats[0] if detected_formats else "generic",
            enrich_mode=_enrich_mode_str if _enrich_active and enrichment else None,
        ),
        analyzed_at=datetime.now(tz=timezone.utc),
    )

    # --- Summarize ---
    if summarize or cfg.summarize.provider != "template":
        effective_provider = provider or cfg.summarize.provider
        summarizer = _build_summarizer(effective_provider, cfg)
        if summarize and effective_provider == "template" and cfg.summarize.api_key:
            _quiet_mode = quiet or cfg.output.quiet
            if not _quiet_mode:
                console.print(
                    "[dim]Tip: API key is set — for AI summary add [bold]--provider anthropic[/bold] "
                    "(or set default: sift config --provider anthropic).[/dim]"
                )
        try:
            report = report.model_copy(update={"summary": summarizer.summarize(report)})
        except Exception as exc:
            console.print(f"[yellow]Warning:[/yellow] Summarization failed: {exc}")

    # --- Validation-only mode ---
    if validate_only:
        if not quiet:
            console.print(f"[green]✓[/green] Validation passed: {len(report.clusters)} cluster(s)")
        raise typer.Exit(0)

    # --- Apply filter (if provided) ---
    if filter:
        try:
            from .filtering import FilterParser
            filter_obj = FilterParser.parse(filter)
            before = len(report.clusters)
            filtered = [c for c in report.clusters if filter_obj.matches(c)]
            after = len(filtered)
            if not (quiet or cfg.output.quiet):
                console.print(f"[dim]Filter '{filter}': {after}/{before} cluster(s) matched.[/dim]")
            report = report.model_copy(update={"clusters": filtered})
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Filter parsing failed: {e}")

    # --- Cache write (opt-in) ---
    if _alert_cache is not None and _cache_key is not None:
        try:
            _alert_cache.put(_cache_key, report.model_dump())
        except Exception:
            pass  # Cache write failure is non-blocking

    # --- Output ---
    _render_output(report, format=format, output_path=output, cfg=cfg, quiet=quiet)

    # --- Exit code ---
    raise typer.Exit(report.exit_code)


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def _render_output(report: TriageReport, *, format: str, output_path: Optional[Path], cfg, quiet: bool) -> None:
    import json

    from .output.export import export_csv, export_json
    from .output.formatter import format_report_console, format_report_rich

    fmt = format.lower()

    if fmt == "rich":
        format_report_rich(report)
        if output_path:
            data = export_json(report)
            output_path.write_text(data, encoding="utf-8")
            if not quiet:
                console.print(f"[dim]Report saved → {output_path}[/dim]")

    elif fmt == "console":
        format_report_console(report)
        if output_path:
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                format_report_console(report)
            output_path.write_text(buf.getvalue(), encoding="utf-8")

    elif fmt == "json":
        data = export_json(report, output_path)
        if not output_path:
            print(data)

    elif fmt == "csv":
        data = export_csv(report, output_path)
        if not output_path:
            print(data)

    elif fmt == "stix":
        try:
            from .output.stix import STIXExporter
            exporter = STIXExporter(report)
            stix_bundle = exporter.to_stix_bundle()
            stix_json = json.dumps(stix_bundle, indent=2, default=str)
            if output_path:
                output_path.write_text(stix_json, encoding="utf-8")
                if not quiet:
                    console.print(f"[dim]STIX bundle saved → {output_path}[/dim]")
            else:
                print(stix_json)
        except ImportError:
            console.print("[red]Error:[/red] STIX export requires sift to be installed with stix support.")
            raise typer.Exit(2)
        except Exception as e:
            console.print(f"[red]Error:[/red] STIX export failed: {e}")
            raise typer.Exit(2)

    else:
        console.print(
            f"[red]Error:[/red] Unknown output format '{format}'. "
            "Valid formats: rich | console | json | csv | stix"
        )
        raise typer.Exit(2)


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------

@app.command()
def validate(
    files: Annotated[list[Path], typer.Argument(
        help="Alert files or directories to validate (JSON, Splunk JSON, CSV). Use '-' for stdin.",
        show_default=False,
    )],
    quiet: Annotated[bool, typer.Option(
        "--quiet", "-q",
        help="Suppress banner.",
    )] = False,
    config_path: Annotated[Optional[Path], typer.Option(
        "--config",
        help="Path to a custom config.yaml.",
        show_default=False,
        hidden=True,
    )] = None,
) -> None:
    """Validate alert files — parse and report format/count without running the full pipeline."""
    cfg = load_config(config_path)

    show_banner(
        quiet=quiet or cfg.output.quiet,
        update_check_enabled=cfg.update_check.enabled,
        check_interval_hours=cfg.update_check.check_interval_hours,
    )

    resolved = _resolve_paths(files)
    if not resolved:
        console.print("[yellow]Warning:[/yellow] No files to validate.")
        raise typer.Exit(0)

    any_error = False
    for path in resolved:
        label = "<stdin>" if str(path) == "-" else path.name
        try:
            if str(path) == "-":
                raw = sys.stdin.read()
            else:
                raw = path.read_text(encoding="utf-8")
        except Exception as exc:
            console.print(f"[red]✗[/red] {label} — Error reading file: {exc}")
            any_error = True
            continue

        if not raw.strip():
            console.print(f"[yellow]✗[/yellow] {label} — Empty file.")
            any_error = True
            continue

        try:
            alerts, fmt = _normalize(raw)
        except Exception as exc:
            console.print(f"[red]✗[/red] {label} — Parse error: {exc}")
            any_error = True
            continue

        if not alerts:
            console.print(f"[yellow]✗[/yellow] {label} — No alerts found (format detected: {fmt}).")
            any_error = True
        else:
            console.print(f"[green]✓[/green] {label} — {len(alerts):,} alert(s) ({fmt})")

    raise typer.Exit(2 if any_error else 0)


# ---------------------------------------------------------------------------
# doctor command
# ---------------------------------------------------------------------------

@app.command()
def doctor() -> None:
    """Run diagnostics — check dependencies, config, and LLM connectivity."""
    from .doctor import print_doctor_report, run_checks

    results = run_checks()
    ok = print_doctor_report(results)
    raise typer.Exit(0 if ok else 1)


# ---------------------------------------------------------------------------
# metrics command
# ---------------------------------------------------------------------------

@app.command()
def metrics(
    file: Annotated[Path, typer.Argument(
        help="Alert file to analyze (JSON, Splunk JSON, CSV). Use '-' for stdin.",
        show_default=False,
    )],
    quiet: Annotated[bool, typer.Option(
        "--quiet", "-q",
        help="Suppress banner.",
    )] = False,
    no_dedup: Annotated[bool, typer.Option(
        "--no-dedup",
        help="Skip alert deduplication.",
    )] = False,
    config_path: Annotated[Optional[Path], typer.Option(
        "--config",
        help="Path to config.yaml",
        show_default=False,
    )] = None,
) -> None:
    """Show metrics for alerts: cluster count, IOC distribution, etc."""
    from .metrics import MetricsCollector

    # --- Load config ---
    cfg = load_config(config_path)

    # --- Banner ---
    show_banner(
        quiet=quiet or cfg.output.quiet,
        update_check_enabled=cfg.update_check.enabled,
        check_interval_hours=cfg.update_check.check_interval_hours,
    )

    # --- Read input ---
    try:
        if str(file) == "-":
            raw = sys.stdin.read()
            input_file_str = "<stdin>"
        else:
            if not file.exists():
                console.print(f"[red]Error:[/red] File not found: {file}")
                raise typer.Exit(2)
            raw = file.read_text(encoding="utf-8")
            input_file_str = str(file)
    except Exception as exc:
        console.print(f"[red]Error reading input:[/red] {exc}")
        raise typer.Exit(2)

    if not raw.strip():
        console.print("[red]Error:[/red] Input is empty.")
        raise typer.Exit(2)

    # --- Normalize ---
    try:
        alerts, detected_format = _normalize(raw)
    except Exception as exc:
        console.print(f"[red]Error during normalization:[/red] {exc}")
        raise typer.Exit(2)

    if not alerts:
        console.print("[yellow]Warning:[/yellow] No alerts could be parsed from input.")
        raise typer.Exit(0)

    alerts_ingested = len(alerts)

    # --- Dedup ---
    if no_dedup:
        alerts_after_dedup = alerts
        dedup_count = alerts_ingested
    else:
        from .pipeline.dedup import DeduplicatorConfig, deduplicate
        alerts_after_dedup, dedup_stats = deduplicate(
            alerts,
            DeduplicatorConfig(time_window_minutes=cfg.clustering.time_window_minutes),
        )
        dedup_count = dedup_stats.deduplicated_count

    # --- IOC extraction ---
    from .pipeline.ioc_extractor import enrich_alerts_iocs
    alerts_after_dedup = enrich_alerts_iocs(alerts_after_dedup)

    # --- Cluster ---
    from .pipeline.clusterer import cluster_alerts
    clusters = cluster_alerts(alerts_after_dedup, cfg.clustering)

    # --- Prioritize ---
    from .pipeline.prioritizer import prioritize_all
    clusters = prioritize_all(clusters, cfg.scoring)

    # --- Build minimal report ---
    report = TriageReport(
        input_file=input_file_str,
        alerts_ingested=alerts_ingested,
        alerts_after_dedup=dedup_count if not no_dedup else alerts_ingested,
        clusters=clusters,
        analyzed_at=datetime.now(tz=timezone.utc),
    )

    # --- Collect and display metrics ---
    metrics_obj = MetricsCollector.collect(report)
    metrics_table = MetricsCollector.format_table(metrics_obj)

    console.print()
    console.print(metrics_table)
    console.print()


# ---------------------------------------------------------------------------
# config command
# ---------------------------------------------------------------------------

@app.command(name="config")
def config_cmd(
    show: Annotated[bool, typer.Option("--show", help="Print current configuration as YAML.")] = False,
    config_path: Annotated[Optional[Path], typer.Option("--config", show_default=False, help="Path to config.yaml.")] = None,
    # --- Credentials (stored in ~/.sift/.env, never in config.yaml) ---
    api_key: Annotated[Optional[str], typer.Option(
        "--api-key",
        help="Set LLM API key (stored in ~/.sift/.env as SIFT_LLM_KEY, never in config.yaml).",
        show_default=False,
    )] = None,
    unset_api_key: Annotated[bool, typer.Option(
        "--unset-api-key",
        help="Remove the LLM API key from ~/.sift/.env.",
    )] = False,
    # --- Summarization ---
    provider: Annotated[Optional[str], typer.Option(
        "--provider",
        help="Default LLM provider: template | anthropic | openai | ollama.",
        show_default=False,
    )] = None,
    model: Annotated[Optional[str], typer.Option(
        "--model",
        help="Default LLM model name (e.g. claude-opus-4-6, gpt-4o). None = auto-select.",
        show_default=False,
    )] = None,
    # --- Output defaults ---
    quiet: Annotated[Optional[bool], typer.Option(
        "--quiet/--no-quiet",
        help="Set quiet mode as default (suppresses banner and status lines).",
    )] = None,
    default_format: Annotated[Optional[str], typer.Option(
        "--default-format",
        help="Default output format: rich | console | json | csv | stix.",
        show_default=False,
    )] = None,
    # --- Pipeline defaults ---
    chunk_size: Annotated[Optional[int], typer.Option(
        "--chunk-size",
        help="Default chunk size for large alert batches (0 = no chunking).",
        show_default=False,
    )] = None,
    cache: Annotated[Optional[bool], typer.Option(
        "--cache/--no-cache",
        help="Enable or disable result caching by default (opt-in, TTL 1h).",
    )] = None,
    enrich_consent: Annotated[Optional[bool], typer.Option(
        "--enrich-consent/--no-enrich-consent",
        help="Pre-approve enrichment consent (skips interactive prompt for --enrich).",
    )] = None,
    redact_fields_default: Annotated[Optional[str], typer.Option(
        "--redact-fields",
        help="Default fields to redact before AI submission (comma-separated, e.g. 'user,host,source_ip'). Use '' to clear.",
        show_default=False,
    )] = None,
) -> None:
    """Show or set sift configuration.

    Settings are persisted to ~/.sift/config.yaml.
    The LLM API key is stored separately in ~/.sift/.env (mode 600).

    \b
    Examples:
      sift config --show
      sift config --api-key sk-ant-...
      sift config --provider anthropic --model claude-opus-4-6
      sift config --quiet --default-format json
      sift config --chunk-size 100 --cache
      sift config --redact-fields user,host,source_ip
      sift config --unset-api-key
    """
    from sift.config import clear_credentials, save_credentials

    import yaml
    from rich.syntax import Syntax

    _VALID_PROVIDERS = {"template", "mock", "anthropic", "openai", "ollama"}
    _VALID_FORMATS = {"rich", "console", "json", "csv", "stix"}

    cfg = load_config(config_path)
    cfg_changed = False
    rich_console = Console()

    # --- Validate inputs early ---
    if provider is not None and provider not in _VALID_PROVIDERS:
        console.print(f"[red]Error:[/red] Invalid provider {provider!r}. Valid: {', '.join(sorted(_VALID_PROVIDERS))}")
        raise typer.Exit(2)
    if default_format is not None and default_format not in _VALID_FORMATS:
        console.print(f"[red]Error:[/red] Invalid format {default_format!r}. Valid: {', '.join(sorted(_VALID_FORMATS))}")
        raise typer.Exit(2)
    if chunk_size is not None and chunk_size < 0:
        console.print("[red]Error:[/red] --chunk-size must be >= 0.")
        raise typer.Exit(2)

    # --- Credentials (never written to config.yaml) ---
    if api_key is not None:
        env_path = save_credentials(api_key)
        console.print(f"[green]✓[/green] API key saved to {env_path}")

    if unset_api_key:
        removed = clear_credentials()
        if removed:
            console.print("[green]✓[/green] API key removed from ~/.sift/.env")
        else:
            console.print("[yellow]No API key found in ~/.sift/.env[/yellow]")

    # --- Config fields ---
    if provider is not None:
        cfg.summarize.provider = provider
        cfg_changed = True
    if model is not None:
        cfg.summarize.model = model
        cfg_changed = True
    if quiet is not None:
        cfg.output.quiet = quiet
        cfg_changed = True
    if default_format is not None:
        cfg.output.default_format = default_format
        cfg_changed = True
    if chunk_size is not None:
        cfg.clustering.chunk_size = chunk_size
        cfg_changed = True
    if cache is not None:
        cfg.cache_enabled = cache
        cfg_changed = True
    if enrich_consent is not None:
        cfg.enrich.consent_given = enrich_consent
        cfg_changed = True
    if redact_fields_default is not None:
        cfg.redaction.fields = [f.strip() for f in redact_fields_default.split(",") if f.strip()]
        cfg_changed = True

    if cfg_changed:
        from sift.config import save_config as _save_config
        saved_path = _save_config(cfg, config_path)
        console.print(f"[green]✓[/green] Config saved to {saved_path}")

    # --- Show ---
    if show:
        data = cfg.model_dump()
        yaml_str = yaml.dump(data, default_flow_style=False, sort_keys=False)
        rich_console.print(Syntax(yaml_str, "yaml", theme="monokai", line_numbers=False))
        return

    # If nothing was done, show usage hint
    if not cfg_changed and not api_key and not unset_api_key:
        typer.echo(
            "Usage: sift config --show\n"
            "       sift config --api-key <key>\n"
            "       sift config --provider <template|anthropic|openai|ollama>\n"
            "       sift config --quiet --default-format json\n"
            "       sift config --redact-fields user,host,source_ip\n"
            "Run 'sift config --help' for all options."
        )


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Print sift version and exit."""
    typer.echo(f"sift v{__version__}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app()


if __name__ == "__main__":
    main()
