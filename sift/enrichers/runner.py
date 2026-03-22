"""EnrichmentRunner — orchestrates barb and vex enrichment for a set of IOCs.

Instantiate once per sift run, call enrich() with the deduplicated IOC list
extracted from alert clusters, and receive an EnrichmentContext ready to be
attached to a TriageReport.
"""

from enum import Enum

from sift.enrichers.barb_bridge import BarbBridge
from sift.enrichers.vex_bridge import VexBridge
from sift.models import EnrichmentContext


class EnrichmentMode(str, Enum):
    BARB = "barb"
    VEX = "vex"
    ALL = "all"


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
        # Deduplicate while preserving order, then cap
        unique_iocs = list(dict.fromkeys(iocs))[:max_iocs]

        barb_results: list[dict] = []
        vex_results: list[dict] = []

        if self.mode in (EnrichmentMode.BARB, EnrichmentMode.ALL):
            url_iocs = [i for i in unique_iocs if self.barb.can_enrich(i)]
            barb_results = self.barb.enrich(url_iocs) if url_iocs else []

        if self.mode in (EnrichmentMode.VEX, EnrichmentMode.ALL):
            vex_iocs = [i for i in unique_iocs if self.vex.can_enrich(i)]
            vex_results = self.vex.enrich(vex_iocs) if vex_iocs else []

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
