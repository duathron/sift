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
        help="Output format: rich | console | json | csv | stix",
    )] = "rich",
    filter: Annotated[Optional[str], typer.Option(
        "--filter",
        help="Filter clusters using boolean DSL (e.g., 'priority >= HIGH')",
    )] = None,
    summarize: Annotated[bool, typer.Option(
        "--summarize", "-s",
        help="Generate AI/template triage summary.",
    )] = False,
    provider: Annotated[Optional[str], typer.Option(
        help="LLM provider: template | mock | anthropic | openai | ollama",
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
    enrich: Annotated[bool, typer.Option(
        "--enrich",
        help="Enrich IOCs via barb (URLs) and vex (all IOCs). Requires consent or --yes.",
    )] = False,
    enrich_mode: Annotated[Optional[str], typer.Option(
        "--enrich-mode",
        help="Enrichment scope: all | barb | vex | local  [default: all]. 'local' = heuristic-only, no external API calls.",
    )] = None,
    yes: Annotated[bool, typer.Option(
        "--yes", "-y",
        help="Skip consent prompt for external API calls (--enrich).",
    )] = False,
    validate_only: Annotated[bool, typer.Option(
        "--validate-only",
        help="Validation-only mode: parse and validate, skip output rendering.",
    )] = False,
    cache: Annotated[bool, typer.Option(
        "--cache",
        help="Cache triage results by input fingerprint (opt-in, TTL 1h).",
    )] = False,
    redact_fields: Annotated[Optional[str], typer.Option(
        "--redact-fields",
        help="Comma-separated alert fields to redact before processing (e.g. 'user,host,source_ip').",
    )] = None,
    chunk_size: Annotated[int, typer.Option(
        "--chunk-size",
        help="Process alerts in chunks of N (0 = no chunking, default). Reduces memory for large files.",
    )] = 0,
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


    # --- Cache lookup (opt-in) ---
    _alert_cache = None
    _cache_key: str | None = None
    if cache:
        import hashlib
        from .cache import AlertCache, CacheConfig
        _cache_key = hashlib.sha256(raw.encode()).hexdigest()
        _alert_cache = AlertCache(CacheConfig(enabled=True))
        _cached = _alert_cache.get(_cache_key)
        if _cached is not None:
            if not quiet:
                console.print("[dim]Cache hit — returning cached triage result.[/dim]")
            _render_output(_cached, format=format, output_path=output, cfg=cfg, quiet=quiet)
            raise typer.Exit(0)

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
        if dedup_stats.removed_count > 0 and not quiet:
            console.print(
                f"[dim]Deduplication: {alerts_ingested} → {dedup_count} alerts "
                f"({dedup_stats.removed_count} duplicates removed)[/dim]"
            )

    # --- Field-level redaction (optional) ---
    if redact_fields:
        fields_to_redact = [f.strip() for f in redact_fields.split(",") if f.strip()]
        alerts_after_dedup = [a.redact(fields_to_redact) for a in alerts_after_dedup]

    # --- IOC extraction ---
    from .pipeline.ioc_extractor import enrich_alerts_iocs
    alerts_after_dedup = enrich_alerts_iocs(alerts_after_dedup)

    # --- Cluster + Prioritize (with optional chunking) ---
    from .pipeline.chunker import chunk_alerts, merge_triage_reports
    from .pipeline.clusterer import cluster_alerts
    from .pipeline.prioritizer import prioritize_all

    effective_chunk_size = chunk_size if chunk_size > 0 else cfg.clustering.chunk_size
    if effective_chunk_size > 0:
        chunks = chunk_alerts(alerts_after_dedup, effective_chunk_size)
        _chunk_reports = []
        for _chunk in chunks:
            _cls = cluster_alerts(_chunk, cfg.clustering)
            _cls = prioritize_all(_cls, cfg.scoring)
            _chunk_reports.append(TriageReport(
                input_file=input_file_str,
                alerts_ingested=len(_chunk),
                alerts_after_dedup=len(_chunk),
                clusters=_cls,
                analyzed_at=datetime.now(tz=timezone.utc),
            ))
        clusters = merge_triage_reports(_chunk_reports).clusters
    else:
        clusters = cluster_alerts(alerts_after_dedup, cfg.clustering)
        clusters = prioritize_all(clusters, cfg.scoring)

    # --- Enrichment (optional) ---
    enrichment = None
    if enrich:
        from .enrichers.runner import EnrichmentMode, EnrichmentRunner
        mode_map = {"barb": EnrichmentMode.BARB, "vex": EnrichmentMode.VEX, "all": EnrichmentMode.ALL, "local": EnrichmentMode.LOCAL}
        eff_mode = mode_map.get((enrich_mode or "all").lower(), EnrichmentMode.ALL)
        # LOCAL mode skips consent prompt — no data leaves the system
        consent = (eff_mode is EnrichmentMode.LOCAL) or _check_enrich_consent(yes, cfg)
        if consent:
            runner = EnrichmentRunner(mode=eff_mode)
            # Collect all unique IOCs from clusters
            all_iocs = runner.collect_iocs_from_report(
                type("R", (), {"clusters": clusters})()
            )
            if all_iocs:
                if not (quiet or cfg.output.quiet):
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
        alerts_ingested=alerts_ingested,
        alerts_after_dedup=dedup_count if not no_dedup else alerts_ingested,
        clusters=clusters,
        enrichment=enrichment,
        manifest=PipelineManifest(
            sift_version=__version__,
            input_format=detected_format,
            enrich_mode=(enrich_mode or "all") if enrich and enrichment else None,
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
            report = report.model_copy(
                update={"clusters": [c for c in report.clusters if filter_obj.matches(c)]}
            )
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
        console.print(f"[yellow]Unknown format '{format}', using rich.[/yellow]")
        format_report_rich(report)


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
    show: Annotated[bool, typer.Option("--show", help="Print current configuration.")] = False,
    config_path: Annotated[Optional[Path], typer.Option("--config", show_default=False)] = None,
) -> None:
    """Show or manage sift configuration."""
    import yaml
    from rich.syntax import Syntax

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
