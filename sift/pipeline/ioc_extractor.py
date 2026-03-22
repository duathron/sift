"""
sift/pipeline/ioc_extractor.py

IOC extraction and alert enrichment for the sift pipeline.

Extracts Indicators of Compromise (IOCs) from free-text fields using
regex patterns, deduplicates results, and populates Alert.iocs in a
non-mutating fashion.
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sift.models import Alert


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# IPv4: four octets, word-bounded to avoid matching version strings etc.
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b"
)

# IPv6: covers full, compressed, and mixed forms (best-effort heuristic).
# The authoritative validation is done via ipaddress.ip_address().
_RE_IPV6 = re.compile(
    r"(?<![:\w])"                       # negative lookbehind
    r"(?:[0-9a-fA-F]{1,4}:){2,7}"      # 2–7 hex groups with colon
    r"(?:[0-9a-fA-F]{1,4}|:)"
    r"|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r"(?![:\w])"
)

# URLs (http / https / ftp)
_RE_URL = re.compile(
    r"(?:https?|ftp)://"
    r"(?:[^\s\"'<>()\[\]{}|\\^`])"
    r"[^\s\"'<>()\[\]{}|\\^`]*",
    re.IGNORECASE,
)

# Domain names — at least one label, a dot, and a recognised TLD-length suffix.
# Filtered post-match against _NON_IOC_TLDS.
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)

# Hashes — anchored to word boundaries so partial matches are avoided.
_RE_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Email addresses (RFC 5321-ish, intentionally loose)
_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# ---------------------------------------------------------------------------
# Filter sets
# ---------------------------------------------------------------------------

# Private / loopback IPv4 networks — candidates are dropped if they fall
# inside any of these ranges.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space
]

# TLD suffixes that are internal/non-routable and therefore not IOCs.
_NON_IOC_TLDS: frozenset[str] = frozenset(
    {
        "local",
        "internal",
        "corp",
        "test",
        "example",
        "invalid",
        "localhost",
        "lan",
        "home",
        "intranet",
        "localdomain",
        "domain",
        "arpa",
    }
)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _is_private_ipv4(addr: str) -> bool:
    """Return True if *addr* is a private/loopback IPv4 address."""
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _is_valid_ipv6(addr: str) -> bool:
    """Return True if *addr* is a syntactically valid, non-loopback IPv6."""
    try:
        ip = ipaddress.ip_address(addr)
        return ip.version == 6 and not ip.is_loopback
    except ValueError:
        return False


def _tld_of(domain: str) -> str:
    """Return the TLD (last label) of *domain*, lower-cased."""
    return domain.rsplit(".", 1)[-1].lower()


def _collect_text_fields(alert: "Alert") -> list[str]:
    """
    Gather all free-text content from an Alert that may contain IOCs.

    Includes: title, description, source_ip, dest_ip, user, host,
    category, and every string value recursively extracted from
    ``alert.raw``.
    """
    fields: list[str] = []

    for value in (
        alert.title,
        alert.description,
        alert.source_ip,
        alert.dest_ip,
        alert.user,
        alert.host,
        alert.category,
    ):
        if value:
            fields.append(value)

    fields.extend(_extract_strings_from_dict(alert.raw))
    return fields


def _extract_strings_from_dict(d: dict) -> list[str]:
    """Recursively collect all string leaf values from a nested dict."""
    results: list[str] = []
    for v in d.values():
        if isinstance(v, str):
            results.append(v)
        elif isinstance(v, dict):
            results.extend(_extract_strings_from_dict(v))
        elif isinstance(v, list):
            results.extend(_extract_strings_from_list(v))
    return results


def _extract_strings_from_list(lst: list) -> list[str]:
    """Recursively collect all string values from a nested list."""
    results: list[str] = []
    for item in lst:
        if isinstance(item, str):
            results.append(item)
        elif isinstance(item, dict):
            results.extend(_extract_strings_from_dict(item))
        elif isinstance(item, list):
            results.extend(_extract_strings_from_list(item))
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_ioc_type(ioc: str) -> str:
    """
    Classify a single IOC string into a type label.

    Parameters
    ----------
    ioc:
        A candidate IOC string that has already been extracted/validated.

    Returns
    -------
    str
        One of ``"ip"``, ``"domain"``, ``"url"``, ``"hash_md5"``,
        ``"hash_sha1"``, ``"hash_sha256"``, ``"email"``, or ``"unknown"``.
    """
    # URL — check before domain so http://evil.com isn't typed as domain.
    if _RE_URL.fullmatch(ioc):
        return "url"

    # Email — check before domain (foo@bar.com ends with a domain).
    if _RE_EMAIL.fullmatch(ioc):
        return "email"

    # IP addresses
    try:
        ip = ipaddress.ip_address(ioc)
        if ip.version in (4, 6):
            return "ip"
    except ValueError:
        pass

    # Hashes — ordered longest-first to prevent SHA256 matching as SHA1/MD5.
    if re.fullmatch(r"[0-9a-fA-F]{64}", ioc):
        return "hash_sha256"
    if re.fullmatch(r"[0-9a-fA-F]{40}", ioc):
        return "hash_sha1"
    if re.fullmatch(r"[0-9a-fA-F]{32}", ioc):
        return "hash_md5"

    # Domain — must look like a multi-label hostname with a valid TLD length.
    if _RE_DOMAIN.fullmatch(ioc) and _tld_of(ioc) not in _NON_IOC_TLDS:
        return "domain"

    return "unknown"


def extract_iocs(text: str) -> list[str]:
    """
    Extract all IOC candidates from an arbitrary text string.

    Processing order matters: URLs are extracted first (and their text
    consumed conceptually), then emails, then IPs, domains, and finally
    hashes.  Deduplication is applied after all patterns are evaluated;
    the result is returned as a sorted list for deterministic output.

    Parameters
    ----------
    text:
        Raw text that may contain IOC strings.

    Returns
    -------
    list[str]
        Deduplicated, sorted list of IOC strings found in *text*.
    """
    candidates: set[str] = set()

    # --- URLs ---
    for m in _RE_URL.finditer(text):
        candidates.add(m.group())

    # --- Email addresses ---
    for m in _RE_EMAIL.finditer(text):
        candidates.add(m.group())

    # --- IPv4 (public only) ---
    for m in _RE_IPV4.finditer(text):
        addr = m.group()
        if not _is_private_ipv4(addr):
            candidates.add(addr)

    # --- IPv6 (validated via ipaddress) ---
    for m in _RE_IPV6.finditer(text):
        addr = m.group().strip()
        if _is_valid_ipv6(addr):
            candidates.add(addr)

    # --- Domain names (non-internal TLDs only) ---
    for m in _RE_DOMAIN.finditer(text):
        domain = m.group()
        if _tld_of(domain) not in _NON_IOC_TLDS:
            # Skip anything that looks like a plain IP already captured above.
            try:
                ipaddress.ip_address(domain)
                continue
            except ValueError:
                pass
            candidates.add(domain)

    # --- Hashes: SHA256 first to prevent prefix collisions ---
    for m in _RE_SHA256.finditer(text):
        candidates.add(m.group().lower())

    for m in _RE_SHA1.finditer(text):
        h = m.group().lower()
        # Skip if it was already captured as part of a longer SHA256 match.
        if not any(existing.startswith(h) and len(existing) > len(h) for existing in candidates):
            candidates.add(h)

    for m in _RE_MD5.finditer(text):
        h = m.group().lower()
        if not any(existing.startswith(h) and len(existing) > len(h) for existing in candidates):
            candidates.add(h)

    return sorted(candidates)


def enrich_alert_iocs(alert: "Alert") -> "Alert":
    """
    Populate ``alert.iocs`` with IOCs extracted from all text fields.

    Scans: ``title``, ``description``, ``source_ip``, ``dest_ip``,
    ``user``, ``host``, ``category``, and all string leaf values within
    ``alert.raw``.  Additionally, ``source_ip`` and ``dest_ip`` are
    included directly when present (they may already be valid IOCs even
    if the regex above would have caught them, but we add them
    unconditionally to be safe).

    The original Alert object is **not mutated**; a new instance is
    returned via ``model_copy(update=...)``.

    Parameters
    ----------
    alert:
        The Alert to enrich.

    Returns
    -------
    Alert
        A new Alert with the ``iocs`` field populated.
    """
    text_blob = "\n".join(_collect_text_fields(alert))
    extracted: set[str] = set(extract_iocs(text_blob))

    # Unconditionally include source_ip / dest_ip when set, regardless of
    # whether they are public, since they represent network context even for
    # RFC-1918 addresses.
    for ip_field in (alert.source_ip, alert.dest_ip):
        if ip_field:
            try:
                ipaddress.ip_address(ip_field)
                extracted.add(ip_field)
            except ValueError:
                pass

    # Merge with any pre-existing IOCs already on the alert
    extracted.update(alert.iocs)

    return alert.model_copy(update={"iocs": sorted(extracted)})


def enrich_alerts_iocs(alerts: "list[Alert]") -> "list[Alert]":
    """
    Apply :func:`enrich_alert_iocs` to every alert in *alerts*.

    Parameters
    ----------
    alerts:
        Sequence of Alert objects to enrich.

    Returns
    -------
    list[Alert]
        New list of enriched Alert instances (originals are not mutated).
    """
    return [enrich_alert_iocs(alert) for alert in alerts]
