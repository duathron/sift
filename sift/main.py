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


# ---------------------------------------------------------------------------
# Helper: resolve normalizer
# ---------------------------------------------------------------------------

def _normalize(raw: str) -> tuple[list, str]:
    """Auto-detect format and return (alerts, format_name)."""
    from .normalizers.splunk import SplunkNormalizer
    from .normalizers.generic import GenericNormalizer
    from .normalizers.csv_normalizer import CSVNormalizer

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

    if provider == "template":
        return TemplateSummarizer()

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
# triage command
# ---------------------------------------------------------------------------

@app.command()
def triage(
    file: Annotated[Path, typer.Argument(
        help="Alert file to triage (JSON, Splunk JSON, CSV). Use '-' for stdin.",
        show_default=False,
    )],
    format: Annotated[str, typer.Option(
        "--format", "-f",
        help="Output format: rich | console | json | csv",
    )] = "rich",
    summarize: Annotated[bool, typer.Option(
        "--summarize", "-s",
        help="Generate AI/template triage summary.",
    )] = False,
    provider: Annotated[Optional[str], typer.Option(
        help="LLM provider: template | anthropic | openai | ollama",
    )] = None,
    output: Annotated[Optional[Path], typer.Option(
        "--output", "-o",
        help="Save output to file.",
    )] = None,
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
    """Triage alerts from FILE: normalize → dedup → cluster → prioritize → output."""

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
        from .pipeline.dedup import deduplicate, DeduplicatorConfig
        alerts_after_dedup, dedup_stats = deduplicate(
            alerts,
            DeduplicatorConfig(time_window_minutes=cfg.clustering.time_window_minutes),
        )
        dedup_count = dedup_stats.deduplicated_count
        if dedup_stats.removed_count > 0 and not quiet:
            console.print(
                f"[dim]Deduplication: {alerts_ingested} → {dedup_count} alerts "
                f"({dedup_stats.removed_count} duplicates removed)[/dim]"
            )

    # --- IOC extraction ---
    from .pipeline.ioc_extractor import enrich_alerts_iocs
    alerts_after_dedup = enrich_alerts_iocs(alerts_after_dedup)

    # --- Cluster ---
    from .pipeline.clusterer import cluster_alerts
    clusters = cluster_alerts(alerts_after_dedup, cfg.clustering)

    # --- Prioritize ---
    from .pipeline.prioritizer import prioritize_all
    clusters = prioritize_all(clusters, cfg.scoring)

    # --- Build report ---
    report = TriageReport(
        input_file=input_file_str,
        alerts_ingested=alerts_ingested,
        alerts_after_dedup=dedup_count if not no_dedup else alerts_ingested,
        clusters=clusters,
        manifest=PipelineManifest(
            sift_version=__version__,
            input_format=detected_format,
        ),
        analyzed_at=datetime.now(tz=timezone.utc),
    )

    # --- Summarize ---
    if summarize or cfg.summarize.provider != "template":
        effective_provider = provider or cfg.summarize.provider
        summarizer = _build_summarizer(effective_provider, cfg)
        try:
            report = report.model_copy(update={"summary": summarizer.summarize(report)})
        except Exception as exc:
            console.print(f"[yellow]Warning:[/yellow] Summarization failed: {exc}")

    # --- Output ---
    _render_output(report, format=format, output_path=output, cfg=cfg, quiet=quiet)

    # --- Exit code ---
    raise typer.Exit(report.exit_code)


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def _render_output(report: TriageReport, *, format: str, output_path: Optional[Path], cfg, quiet: bool) -> None:
    from .output.formatter import format_report_rich, format_report_console
    from .output.export import export_json, export_csv

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
            import io, contextlib
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

    else:
        console.print(f"[yellow]Unknown format '{format}', using rich.[/yellow]")
        format_report_rich(report)


# ---------------------------------------------------------------------------
# doctor command
# ---------------------------------------------------------------------------

@app.command()
def doctor() -> None:
    """Run diagnostics — check dependencies, config, and LLM connectivity."""
    from .doctor import run_checks, print_doctor_report

    results = run_checks()
    ok = print_doctor_report(results)
    raise typer.Exit(0 if ok else 1)


# ---------------------------------------------------------------------------
# config command
# ---------------------------------------------------------------------------

@app.command(name="config")
def config_cmd(
    show: Annotated[bool, typer.Option("--show", help="Print current configuration.")] = False,
    config_path: Annotated[Optional[Path], typer.Option("--config", show_default=False)] = None,
) -> None:
    """Show or manage sift configuration."""
    from rich.syntax import Syntax
    import yaml

    cfg = load_config(config_path)

    if show:
        rich_console = Console()
        data = cfg.model_dump()
        yaml_str = yaml.dump(data, default_flow_style=False, sort_keys=False)
        rich_console.print(Syntax(yaml_str, "yaml", theme="monokai", line_numbers=False))
    else:
        typer.echo("Usage: sift config --show")


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
