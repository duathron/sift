"""Pipeline stages — dedup → ioc_extract → cluster → prioritize."""

from sift.pipeline.dedup import DeduplicatorConfig, DedupStats, deduplicate

__all__ = [
    "deduplicate",
    "DeduplicatorConfig",
    "DedupStats",
]
