"""EnricherProtocol — structural interface for all enrichment bridges."""

from typing import Protocol, runtime_checkable


@runtime_checkable
class EnricherProtocol(Protocol):
    """Structural protocol that all enricher bridges must satisfy."""

    @property
    def name(self) -> str:
        """Human-readable identifier for this enricher (e.g. 'barb', 'vex')."""
        ...

    def can_enrich(self, ioc: str) -> bool:
        """Return True if this enricher handles the given IOC type."""
        ...

    def enrich(self, iocs: list[str]) -> list[dict]:
        """Enrich a list of IOCs. Returns a list of result dicts (one per IOC)."""
        ...
