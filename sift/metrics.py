"""Metrics collection and reporting for sift triage reports."""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel
from rich.table import Table

from .models import TriageReport


class TriageMetrics(BaseModel):
    """Metrics computed from a TriageReport."""

    cluster_count: int
    alert_count: int
    avg_cluster_size: float
    top_categories: dict[str, int]  # category → count
    ioc_distribution: dict[str, int]  # ioc_type → count
    ai_success_rate: float  # % of clusters with AI summary
    processing_time_seconds: float = 0.0


class MetricsCollector:
    """Collects metrics from a TriageReport."""

    @staticmethod
    def collect(report: TriageReport) -> TriageMetrics:
        """Extract metrics from a TriageReport.

        Args:
            report: Fully processed TriageReport with clusters and alerts.

        Returns:
            TriageMetrics object with computed metrics.
        """
        cluster_count = len(report.clusters)
        alert_count = len([a for c in report.clusters for a in c.alerts])

        # Average cluster size
        avg_cluster_size = (
            alert_count / cluster_count if cluster_count > 0 else 0.0
        )

        # Top 5 categories
        all_categories = [
            a.category
            for c in report.clusters
            for a in c.alerts
            if a.category
        ]
        category_counter = Counter(all_categories)
        top_categories = dict(category_counter.most_common(5))

        # IOC distribution by type
        all_iocs = [ioc for c in report.clusters for ioc in c.iocs]
        ioc_types = MetricsCollector._classify_iocs(all_iocs)
        ioc_distribution = dict(Counter(ioc_types).most_common(10))

        # AI success rate (clusters with summaries)
        ai_success = 0
        if report.summary and report.summary.cluster_summaries:
            clusters_with_summary = set(
                cs.cluster_id for cs in report.summary.cluster_summaries
            )
            ai_success = len(clusters_with_summary)

        ai_success_rate = (
            (ai_success / cluster_count * 100) if cluster_count > 0 else 0.0
        )

        return TriageMetrics(
            cluster_count=cluster_count,
            alert_count=alert_count,
            avg_cluster_size=avg_cluster_size,
            top_categories=top_categories,
            ioc_distribution=ioc_distribution,
            ai_success_rate=ai_success_rate,
            processing_time_seconds=0.0,
        )

    @staticmethod
    def _classify_iocs(iocs: list[str]) -> list[str]:
        """Classify IOCs into types (IPv4, IPv6, domain, hash, URL, email).

        Args:
            iocs: List of IOC strings.

        Returns:
            List of IOC type labels.
        """
        from ipaddress import AddressValueError, ip_address

        types = []
        for ioc in iocs:
            # Check for URL (contains :// or typical URL prefixes)
            if "://" in ioc or ioc.startswith(("http", "ftp")):
                types.append("url")
            # Check for email (contains @)
            elif "@" in ioc:
                types.append("email")
            # Check for IPv4 or IPv6
            elif ":" in ioc and not ioc.startswith("["):
                # Could be IPv6
                try:
                    addr = ip_address(ioc.split("%")[0])
                    types.append("ipv6" if addr.version == 6 else "ipv4")
                except (AddressValueError, ValueError):
                    types.append("unknown")
            else:
                # Try IPv4 first
                try:
                    addr = ip_address(ioc)
                    types.append("ipv4" if addr.version == 4 else "ipv6")
                except (AddressValueError, ValueError):
                    # Check for hash patterns (32/40/64 hex chars)
                    if all(c in "0123456789abcdefABCDEF" for c in ioc):
                        if len(ioc) == 32:
                            types.append("md5")
                        elif len(ioc) == 40:
                            types.append("sha1")
                        elif len(ioc) == 64:
                            types.append("sha256")
                        else:
                            types.append("hash")
                    # Assume domain
                    elif "." in ioc:
                        types.append("domain")
                    else:
                        types.append("unknown")

        return types

    @staticmethod
    def format_table(metrics: TriageMetrics) -> Table:
        """Format metrics as a Rich Table.

        Args:
            metrics: TriageMetrics object.

        Returns:
            Rich Table ready for printing.
        """
        table = Table(title="Triage Metrics", show_header=True)
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", justify="right")

        table.add_row("Clusters", str(metrics.cluster_count))
        table.add_row("Total Alerts", str(metrics.alert_count))
        table.add_row(
            "Avg Cluster Size", f"{metrics.avg_cluster_size:.2f}"
        )
        table.add_row(
            "AI Success Rate", f"{metrics.ai_success_rate:.1f}%"
        )

        # Top categories
        if metrics.top_categories:
            table.add_row("[bold]Top Categories[/bold]", "")
            for cat, count in metrics.top_categories.items():
                table.add_row(f"  {cat}", str(count))

        # IOC distribution
        if metrics.ioc_distribution:
            table.add_row("[bold]IOC Distribution[/bold]", "")
            for ioc_type, count in metrics.ioc_distribution.items():
                table.add_row(f"  {ioc_type}", str(count))

        return table
