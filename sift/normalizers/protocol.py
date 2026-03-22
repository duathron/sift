"""NormalizerProtocol — interface all input normalizers must implement."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Alert


@runtime_checkable
class NormalizerProtocol(Protocol):
    """Convert raw SIEM data (string) to a list of normalized Alert objects."""

    @property
    def name(self) -> str:
        """Short identifier, e.g. 'generic', 'splunk', 'csv'."""
        ...

    def can_handle(self, raw: str) -> bool:
        """Return True if this normalizer can parse the given raw input."""
        ...

    def normalize(self, raw: str) -> list[Alert]:
        """Parse raw input and return a list of Alert objects.

        Must never raise — return an empty list on parse failure.
        """
        ...
