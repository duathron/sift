"""Local heuristic IOC analysis — no network calls, no external APIs."""

from __future__ import annotations

import ipaddress
import math
import re

# Suspicious TLDs often used in phishing and malware campaigns
_SUSPICIOUS_TLDS = frozenset(
    {".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".xyz", ".click", ".loan", ".work"}
)

# Keywords in domains/URLs that suggest credential phishing
_SUSPICIOUS_KEYWORDS = frozenset(
    {"login", "secure", "update", "verify", "account", "signin", "banking", "password", "webscr"}
)

# Regex for IP embedded in URL path or hostname
_IP_IN_URL = re.compile(
    r"https?://(\d{1,3}\.){3}\d{1,3}"
)

# Hash patterns
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_hostname(ioc: str) -> str:
    """Best-effort hostname extraction from URL or raw domain."""
    s = ioc.lower()
    for prefix in ("https://", "http://", "hxxps://", "hxxp://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    # Strip path
    s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return s


def analyze(ioc: str) -> dict:
    """Return heuristic analysis of *ioc* without any network calls.

    Returns a dict with keys:
        ioc       — the original string
        source    — "local_heuristics"
        findings  — list[str], each a finding label
    """
    findings: list[str] = []

    # --- Hash identification ---
    if _MD5_RE.match(ioc):
        findings.append("hash:md5")
    elif _SHA1_RE.match(ioc):
        findings.append("hash:sha1")
    elif _SHA256_RE.match(ioc):
        findings.append("hash:sha256")
    else:
        # --- IP address checks ---
        try:
            addr = ipaddress.ip_address(ioc)
            findings.append("ip:ipv6" if addr.version == 6 else "ip:ipv4")
            if addr.is_private:
                findings.append("ip:private")
            if addr.is_loopback:
                findings.append("ip:loopback")
            if addr.is_multicast:
                findings.append("ip:multicast")
        except ValueError:
            pass

        # --- URL / domain checks ---
        hostname = _extract_hostname(ioc)

        if _IP_IN_URL.match(ioc.lower()):
            findings.append("url:ip_in_url")

        # Suspicious TLD
        for tld in _SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                findings.append(f"domain:suspicious_tld:{tld}")
                break

        # Suspicious keyword
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in hostname:
                findings.append(f"domain:suspicious_keyword:{kw}")
                break

        # High-entropy hostname (possible DGA)
        # Use only the registered domain part (strip www.)
        h = hostname.removeprefix("www.")
        # Strip TLD for entropy check
        parts = h.rsplit(".", 1)
        label = parts[0] if len(parts) > 1 else h
        if label and _shannon_entropy(label) > 3.8:
            findings.append("domain:high_entropy")

    return {
        "ioc": ioc,
        "source": "local_heuristics",
        "findings": findings,
    }
