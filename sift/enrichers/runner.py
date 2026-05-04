"""EnrichmentRunner — orchestrates barb and vex enrichment for a set of IOCs.

Instantiate once per sift run, call enrich() with the deduplicated IOC list
extracted from alert clusters, and receive an EnrichmentContext ready to be
attached to a TriageReport.
"""

import re
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

from sift.enrichers.barb_bridge import BarbBridge
from sift.enrichers.vex_bridge import VexBridge
from sift.models import EnrichmentContext

_RE_HEX = re.compile(r"^[0-9a-fA-F]{32,128}$")
_SCHEME_PREFIX = re.compile(r"^(?:hxxps?|hxtps?|fxp)://", re.IGNORECASE)


def _normalize_ioc(ioc: str) -> str:
    """Lowercase hashes and refang URL schemes so cache keys collapse variants."""
    if _RE_HEX.match(ioc):
        return ioc.lower()
    if _SCHEME_PREFIX.match(ioc):
        from sift.pipeline.ioc_extractor import _refang
        return _refang(ioc)
    return ioc


class EnrichmentMode(str, Enum):
    BARB = "barb"
    VEX = "vex"
    ALL = "all"
    LOCAL = "local"  # heuristic-only, no external API calls


class EnrichmentRunner:
    """Orchestrates optional IOC enrichment via barb and/or vex.

    Parameters
    ----------
    mode:
        Which enrichers to activate. Defaults to ALL (both barb and vex).
    """

    def __init__(self, mode: EnrichmentMode = EnrichmentMode.ALL) -> None:
        self.barb = BarbBridge()
        self.vex = VexBridge()
        self.mode = mode

    def enrich(self, iocs: list[str], max_iocs: int = 20) -> EnrichmentContext:
        """Enrich up to *max_iocs* unique IOCs and return an EnrichmentContext.

        Parameters
        ----------
        iocs:
            Raw list of IOC strings (may contain duplicates).
        max_iocs:
            Hard cap on how many IOCs are enriched (after dedup). Prevents
            runaway API usage on noisy alert sets. Default: 20.

        Returns
        -------
        EnrichmentContext
            Populated with barb_results and/or vex_results as requested.
        """
        # Normalize (lowercase hashes, refang URL schemes) then deduplicate and cap.
        normalized = [_normalize_ioc(ioc) for ioc in iocs]
        unique_iocs = list(dict.fromkeys(normalized))[:max_iocs]

        barb_results: list[dict] = []
        vex_results: list[dict] = []

        if self.mode is EnrichmentMode.LOCAL:
            from sift.enrichers.local_heuristics import analyze
            local_results = [analyze(ioc) for ioc in unique_iocs]
            # Surface local results as barb_results so downstream rendering works
            return EnrichmentContext(barb_results=local_results, vex_results=[])

        # Run barb and vex concurrently — each may block for up to 30 s per IOC.
        with ThreadPoolExecutor(max_workers=4) as pool:
            barb_future = None
            vex_future = None

            if self.mode in (EnrichmentMode.BARB, EnrichmentMode.ALL):
                url_iocs = [i for i in unique_iocs if self.barb.can_enrich(i)]
                if url_iocs:
                    barb_future = pool.submit(self.barb.enrich, url_iocs)

            if self.mode in (EnrichmentMode.VEX, EnrichmentMode.ALL):
                vex_iocs = [i for i in unique_iocs if self.vex.can_enrich(i)]
                if vex_iocs:
                    vex_future = pool.submit(self.vex.enrich, vex_iocs)

            if barb_future is not None:
                barb_results = barb_future.result()
            if vex_future is not None:
                vex_results = vex_future.result()

        return EnrichmentContext(barb_results=barb_results, vex_results=vex_results)

    @staticmethod
    def collect_iocs_from_report(report) -> list[str]:
        """Collect all unique IOCs across every cluster in a TriageReport.

        Parameters
        ----------
        report:
            A ``sift.models.TriageReport`` instance.

        Returns
        -------
        list[str]
            Deduplicated IOCs in first-seen order.
        """
        seen: set[str] = set()
        result: list[str] = []
        for cluster in report.clusters:
            for ioc in cluster.iocs:
                if ioc not in seen:
                    seen.add(ioc)
                    result.append(ioc)
        return result
