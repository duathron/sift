"""
sift/pipeline/ioc_extractor.py

IOC extraction and alert enrichment for the sift pipeline.

Extracts Indicators of Compromise (IOCs) from free-text fields using
regex patterns, deduplicates results, and populates Alert.iocs in a
non-mutating fashion.

v1.1.10 expansion (2026-05-01) covers:

* Defang refang preprocessor (``hxxp://``, ``[.]``, ``(.)``, ``[at]``,
  ``[dot]``, fullwidth ``．`` / ``＠``, zero-width strip).
* CVE IDs (``CVE-YYYY-NNNN``).
* MITRE ATT&CK technique IDs (``T####`` / ``T####.###``).
* PowerShell encoded blocks (``-enc <b64>`` / ``FromBase64String``).
* Tunnel/abuse domain tagging (ngrok / serveo / trycloudflare / pastebin
  / discord webhook / telegram bot URLs) — severity hint surfaced.
* Extended hashes: SHA512, ssdeep, tlsh, JARM (unique sizes); JA3 / JA3S
  / imphash via keyword-anchored extraction (collide with MD5 by size).
* Windows registry keys + persistence-key severity hint.
* Email is now extracted *and surfaced* (was silently filtered before).
* Communication-IOC routing helper :func:`classify_severity_hint`.
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sift.models import Alert


__all__ = [
    "classify_severity_hint",
    "detect_ioc_type",
    "enrich_alert_iocs",
    "enrich_alerts_iocs",
    "extract_iocs",
]


# ---------------------------------------------------------------------------
# Compiled regex patterns — network observables
# ---------------------------------------------------------------------------

# IPv4: four octets, word-bounded to avoid matching version strings etc.
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b"
)

# IPv6: covers full, compressed, and mixed forms (best-effort heuristic).
# The authoritative validation is done via ipaddress.ip_address().
#
# The token alternation ``[0-9a-fA-F]{1,4}:|:`` means each repeated unit can
# be either a normal ``hex:`` group or a bare ``:`` (which lets us cross the
# ``::`` shorthand). 2–7 such units followed by a final ``hex`` group covers
# every common form including ``2606:4700:4700::1111``.
#
# The atomic group ``(?>...)`` (Python 3.11+) prevents catastrophic
# backtracking on long ``aaaa:aaaa:...`` style adversarial inputs.
_RE_IPV6 = re.compile(
    r"(?<![:\w])"
    r"(?>(?:[0-9a-fA-F]{1,4}:|:){2,7})[0-9a-fA-F]{1,4}"
    r"(?![:\w])"
)

# URLs (http / https / ftp). After refang, ``hxxp://`` already became
# ``http://`` so this regex handles both. Trailing sentence punctuation
# (``.``, ``,``, ``;``, ``:``, ``)``, ``"``, ``'``) is stripped post-match
# so prose like ``visit https://evil.com.`` does not capture the period.
_RE_URL = re.compile(
    r"(?:https?|ftp)://"
    r"(?:[^\s\"'<>()\[\]{}|\\^`])"
    r"[^\s\"'<>()\[\]{}|\\^`]*",
    re.IGNORECASE,
)

_URL_TRAILING_PUNCT = ".,;:!?)]}\"'"

# Domain names — at least one label, a dot, and a recognised TLD-length suffix.
# Filtered post-match against _NON_IOC_TLDS.
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)

# ---------------------------------------------------------------------------
# Compiled regex patterns — hashes
# ---------------------------------------------------------------------------

# Hashes — anchored to word boundaries so partial matches are avoided.
# Order matters at extraction time: longest first to suppress prefix matches.
_RE_SHA512 = re.compile(r"\b[0-9a-fA-F]{128}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")

# JARM is a 62-char hex fingerprint — unique size, no collision risk.
# Case-insensitive for vendor feeds that emit uppercase variants.
_RE_JARM = re.compile(r"\b[0-9a-fA-F]{62}\b")

# TLSH: 70 or 72 hex chars, optional ``T1`` prefix.
_RE_TLSH = re.compile(r"\bT?1?[A-F0-9]{70,72}\b", re.IGNORECASE)

# ssdeep: ``<blocksize>:<hash1>:<hash2>``
_RE_SSDEEP = re.compile(
    r"\b\d{1,8}:[A-Za-z0-9+/]{3,128}:[A-Za-z0-9+/]{3,128}\b"
)

# Keyword-anchored hashes — same byte-size as MD5 so we only extract the hex
# blob when we see an unambiguous label first. Matches:
#   JA3=e7d705a3286e19ea42f587b344ee6865
#   JA3S: 4835b...
#   imphash: f34d5f...
#   IMPHASH=00000000... (sentinel, will be filtered later)
_RE_JA3_KEYED = re.compile(
    r"\b(?:ja3s?|imphash)\s*[:=]\s*([0-9a-f]{32})\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Compiled regex patterns — files / paths / persistence
# ---------------------------------------------------------------------------

# Suspicious filenames — Windows executables / scripts. Allows underscores so
# malware names like ``OUTSTANDING_GUTTER.exe`` are captured (the domain regex
# excludes underscores per RFC 1035 and would miss them otherwise).
_RE_FILENAME = re.compile(
    r"\b[A-Za-z0-9_][A-Za-z0-9_\-]{0,254}"
    # Note: ``.com`` is intentionally excluded — DOS-era COM binaries are
    # essentially extinct and the extension collides with the .com TLD,
    # which would mis-classify every commercial domain as a filename.
    r"\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|scr|msi|jar|hta|wsf|lnk|"
    r"rb|pl|php|py|sh|cpl|inf|reg|psm1|psd1|chm|jse|wsh|ocx|drv|"
    r"docm|xlsm|pptm|dotm|xlam|xlsb|iso|img|vhd)"
    r"\b",
    re.IGNORECASE,
)

# Email addresses (RFC 5321-ish, intentionally loose)
_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# Windows registry keys. Lookahead ensures we stop at whitespace, quotes, or
# common delimiters. Captures full path including value name when present.
_RE_REGKEY = re.compile(
    r"\bHK(?:LM|CU|CR|U|CC|EY_LOCAL_MACHINE|EY_CURRENT_USER|"
    r"EY_CLASSES_ROOT|EY_USERS|EY_CURRENT_CONFIG)"
    r"\\[^\s\"'<>|]+",
    re.IGNORECASE,
)

# PowerShell encoded blocks — high-signal indicator of obfuscated execution.
# Captures the base64 payload after ``-enc[odedcommand]`` or
# ``FromBase64String("...")``. Min 100 chars to avoid false positives on
# accidental short b64 strings.
_RE_PS_ENCODED = re.compile(
    r"(?:(?:-|/)e(?:nc|ncoded(?:command)?)\s+|"
    r"FromBase64String\s*\(\s*[\"'])"
    r"([A-Za-z0-9+/=]{100,})",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Compiled regex patterns — vulnerability / framework references
# ---------------------------------------------------------------------------

# CVE IDs.
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# MITRE ATT&CK technique IDs (T1### or T1###.###).
# Restricted to ``T1`` prefix — every real ATT&CK enterprise technique ID
# falls in the T1xxx range (T1001–T1699 currently). This drastically cuts
# false positives on prose like ``T2024 model`` or random ticket IDs while
# still covering the entire published ATT&CK catalogue.
_RE_MITRE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")

# ---------------------------------------------------------------------------
# Defang patterns — refanged before extraction
# ---------------------------------------------------------------------------

# Each pair = (compiled regex, replacement). Order matters: scheme-level
# replacements run before separator-level ones.
#
# ``[at]``/``(at)``/``{at}`` are refanged only when followed by a
# domain-shape token within 60 characters (lookahead requires word chars
# plus a literal ``.`` or ``[dot]``). Without the lookahead we would corrupt
# prose like ``state[at]rest`` or ``array[at]index`` into bogus emails.
_AT_DOMAIN_LOOKAHEAD = r"(?=[A-Za-z0-9._\-]{1,60}(?:\[dot\]|\.))"

_DEFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Schemes
    (re.compile(r"\bhxxp(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bhxtp(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bfxp://", re.IGNORECASE), r"ftp://"),
    # Bracketed separators (always safe — ``[.]`` is overwhelmingly a defang)
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    # Word-form dot separators (rarely seen outside defang contexts).
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\{dot\}", re.IGNORECASE), "."),
    # @ sign — only refang when domain-shape follows; avoids corrupting
    # prose like ``state[at]rest``.
    (re.compile(r"\[at\]" + _AT_DOMAIN_LOOKAHEAD, re.IGNORECASE), "@"),
    (re.compile(r"\(at\)" + _AT_DOMAIN_LOOKAHEAD, re.IGNORECASE), "@"),
    (re.compile(r"\{at\}" + _AT_DOMAIN_LOOKAHEAD, re.IGNORECASE), "@"),
    # Fullwidth Unicode lookalikes
    (re.compile("．"), "."),   # FULLWIDTH FULL STOP
    (re.compile("＠"), "@"),   # FULLWIDTH COMMERCIAL AT
    (re.compile("："), ":"),   # FULLWIDTH COLON
    (re.compile("／"), "/"),   # FULLWIDTH SOLIDUS
]

# Zero-width / BOM characters stripped before matching.
_ZERO_WIDTH_TABLE = {
    0x200B: None,  # ZERO WIDTH SPACE
    0x200C: None,  # ZERO WIDTH NON-JOINER
    0x200D: None,  # ZERO WIDTH JOINER
    0xFEFF: None,  # ZERO WIDTH NO-BREAK SPACE / BOM
    0x2060: None,  # WORD JOINER
}

# ---------------------------------------------------------------------------
# Filter / classification sets
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
        "local", "internal", "corp", "test", "example", "invalid",
        "localhost", "lan", "home", "intranet", "localdomain",
        "domain", "arpa",
    }
)

# Tunnel / cloud-abuse hostname suffixes — auto-tagged as HIGH severity.
_TUNNEL_SUFFIXES: tuple[str, ...] = (
    ".ngrok.io", ".ngrok.app", ".ngrok-free.app",
    ".serveo.net",
    ".trycloudflare.com",
    ".loca.lt", ".localtunnel.me",
    ".pagekite.me",
    ".tunnelmole.com",
    ".bore.pub",
)

# Paste / dump host suffixes — auto-tagged as HIGH severity.
_PASTE_HOSTS: frozenset[str] = frozenset(
    {
        "pastebin.com", "paste.ee", "ghostbin.co", "hastebin.com",
        "rentry.co", "controlc.com", "dpaste.com",
    }
)

# C2-abuse hostnames (legitimate services frequently abused as command
# channels). Matched against full hostname plus URL-path heuristics in
# :func:`classify_severity_hint`.
_C2_ABUSE_HOSTS: frozenset[str] = frozenset(
    {"discord.com", "discordapp.com", "t.me", "api.telegram.org"}
)

# Registry keys whose presence implies persistence (auto-HIGH).
_PERSISTENCE_REG_FRAGMENTS: tuple[str, ...] = (
    r"\\Run",
    r"\\RunOnce",
    r"\\Image File Execution Options",
    r"\\Services\\",
    r"\\Winlogon\\",
    r"\\AppInit_DLLs",
    r"\\Active Setup",
    r"\\ShellServiceObjectDelayLoad",
)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _refang(text: str) -> str:
    """Return *text* with common defanging patterns reversed.

    Handles ``hxxp://``, ``[.]``, ``(.)``, ``[at]``, ``[dot]``,
    fullwidth Unicode lookalikes, and zero-width invisibles. Idempotent.
    """
    if not text:
        return text
    # Strip zero-width characters first so they don't break later regexes.
    text = text.translate(_ZERO_WIDTH_TABLE)
    for rx, repl in _DEFANG_PATTERNS:
        text = rx.sub(repl, text)
    return text


# Hashes of the empty byte string (``""``) — emitted by tools that compute a
# digest of a missing/zero-length file. These are pure noise in IOC lists.
_EMPTY_STRING_HASHES: frozenset[str] = frozenset({
    "d41d8cd98f00b204e9800998ecf8427e",                                    # MD5("")
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                            # SHA1("")
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",    # SHA256("")
})


def _is_null_hash(h: str) -> bool:
    """Return True if *h* is a sentinel/null hash.

    Three classes of sentinel are detected:

    1. All zeros (``00…00``) — Sysmon ``IMPHASH`` for binaries without an
       import table.
    2. All ``f`` (``ff…ff``) — common placeholder for "value missing".
    3. Hashes of the empty byte string — emitted by tools digesting a
       missing or zero-length artefact.
    """
    if not h:
        return False
    low = h.lower()
    if low == "0" * len(low) or low == "f" * len(low):
        return True
    return low in _EMPTY_STRING_HASHES


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


def _hostname_of(url_or_domain: str) -> str:
    """Return lowercase hostname for a URL or bare domain.

    Strips scheme, userinfo, port, path, query, and fragment.
    """
    s = url_or_domain.strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[1]
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.split("#", 1)[0]
    s = s.split(":", 1)[0]
    return s


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

    Returns one of:
        ``"ip"``, ``"domain"``, ``"url"``, ``"email"``, ``"filename"``,
        ``"hash_md5"``, ``"hash_sha1"``, ``"hash_sha256"``, ``"hash_sha512"``,
        ``"ssdeep"``, ``"tlsh"``, ``"jarm"``,
        ``"cve"``, ``"mitre_technique"``,
        ``"registry_key"``, ``"ps_encoded"``,
        or ``"unknown"``.
    """
    # Order matters. Most-specific patterns first.

    # PowerShell encoded sentinel (synthetic — emitted by extract_iocs).
    if ioc.startswith("ps_encoded:"):
        return "ps_encoded"

    # CVE / MITRE — highly distinctive prefixes.
    if _RE_CVE.fullmatch(ioc):
        return "cve"
    if _RE_MITRE.fullmatch(ioc):
        return "mitre_technique"

    # Registry key (HK* prefix is distinctive).
    if _RE_REGKEY.fullmatch(ioc):
        return "registry_key"

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

    # ssdeep has a unique colon-separated structure.
    if _RE_SSDEEP.fullmatch(ioc):
        return "ssdeep"

    # TLSH (70 or 72 hex with optional T1 prefix).
    if _RE_TLSH.fullmatch(ioc):
        return "tlsh"

    # Hashes — ordered longest-first to prevent SHA256 matching as SHA1/MD5.
    # Null-sentinel hashes are downgraded to "unknown" so callers can drop them.
    if re.fullmatch(r"[0-9a-fA-F]{128}", ioc) and not _is_null_hash(ioc):
        return "hash_sha512"
    if re.fullmatch(r"[0-9a-fA-F]{64}", ioc) and not _is_null_hash(ioc):
        return "hash_sha256"
    if re.fullmatch(r"[0-9a-fA-F]{62}", ioc) and not _is_null_hash(ioc):
        return "jarm"
    if re.fullmatch(r"[0-9a-fA-F]{40}", ioc) and not _is_null_hash(ioc):
        return "hash_sha1"
    if re.fullmatch(r"[0-9a-fA-F]{32}", ioc) and not _is_null_hash(ioc):
        return "hash_md5"

    # Filename — Windows executable / script.
    if _RE_FILENAME.fullmatch(ioc):
        return "filename"

    # Domain — must look like a multi-label hostname with a valid TLD length.
    if _RE_DOMAIN.fullmatch(ioc) and _tld_of(ioc) not in _NON_IOC_TLDS:
        return "domain"

    return "unknown"


def classify_severity_hint(ioc: str) -> str | None:
    """
    Return a severity-hint label for *ioc*, or ``None`` if no hint applies.

    Hints are advisory only — they let downstream clustering / prioritisation
    boost a cluster that contains tunnel domains, persistence registry keys,
    PowerShell encoded blocks, etc.

    Returns ``"high"``, ``"critical"``, or ``None``.
    """
    # PowerShell encoded execution = critical (clear obfuscation intent).
    if ioc.startswith("ps_encoded:"):
        return "critical"

    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "registry_key":
        for frag in _PERSISTENCE_REG_FRAGMENTS:
            if re.search(frag, ioc, re.IGNORECASE):
                return "high"
        return None

    if ioc_type in ("url", "domain"):
        host = _hostname_of(ioc)
        # Tunnel suffix — high.
        if any(host.endswith(suf) for suf in _TUNNEL_SUFFIXES):
            return "high"
        # Paste host — high.
        if host in _PASTE_HOSTS:
            return "high"
        # C2-abuse host: only flag for URLs that look like webhook / bot paths.
        if host in _C2_ABUSE_HOSTS:
            if ioc_type == "url" and re.search(
                r"/(?:api/webhooks|bot[0-9]+:)", ioc, re.IGNORECASE
            ):
                return "high"

    return None


def extract_iocs(text: str) -> list[str]:
    """
    Extract all IOC candidates from an arbitrary text string.

    *text* is first refanged (``hxxp://`` -> ``http://`` etc.) so that
    obfuscated indicators are detected by the normal regex patterns.

    Processing order matters: longest hash patterns first to suppress
    prefix collisions, then keyword-anchored hashes, network observables,
    then framework references.
    """
    if not text:
        return []

    text = _refang(text)

    candidates: set[str] = set()

    # --- URLs ---
    for m in _RE_URL.finditer(text):
        url = m.group().rstrip(_URL_TRAILING_PUNCT)
        if "://" in url and len(url) > len(m.group().split("://", 1)[0]) + 3:
            candidates.add(url)

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
            try:
                ipaddress.ip_address(domain)
                continue
            except ValueError:
                pass
            candidates.add(domain)

    # --- Suspicious filenames ---
    for m in _RE_FILENAME.finditer(text):
        candidates.add(m.group())

    # --- ssdeep (must run before raw-hex hashes since it contains digits) ---
    ssdeep_matches: list[str] = []
    for m in _RE_SSDEEP.finditer(text):
        ssdeep_matches.append(m.group())
        candidates.add(m.group())

    # --- TLSH ---
    for m in _RE_TLSH.finditer(text):
        candidates.add(m.group())

    # --- Hashes: SHA512 first, then SHA256, JARM (62), SHA1, MD5 ---
    for m in _RE_SHA512.finditer(text):
        h = m.group().lower()
        if _is_null_hash(h):
            continue
        candidates.add(h)

    for m in _RE_SHA256.finditer(text):
        h = m.group().lower()
        if _is_null_hash(h):
            continue
        if not any(
            existing.startswith(h) and len(existing) > len(h)
            for existing in candidates
        ):
            candidates.add(h)

    for m in _RE_JARM.finditer(text):
        h = m.group().lower()
        if _is_null_hash(h):
            continue
        if not any(
            existing.startswith(h) and len(existing) > len(h)
            for existing in candidates
        ):
            candidates.add(h)

    for m in _RE_SHA1.finditer(text):
        h = m.group().lower()
        if _is_null_hash(h):
            continue
        if not any(
            existing.startswith(h) and len(existing) > len(h)
            for existing in candidates
        ):
            candidates.add(h)

    for m in _RE_MD5.finditer(text):
        h = m.group().lower()
        if _is_null_hash(h):
            continue
        if not any(
            existing.startswith(h) and len(existing) > len(h)
            for existing in candidates
        ):
            candidates.add(h)

    # --- Keyword-anchored fingerprints (JA3 / JA3S / imphash) ---
    # These collide in size with MD5; the keyword anchor is the signal.
    for m in _RE_JA3_KEYED.finditer(text):
        h = m.group(1).lower()
        if not _is_null_hash(h):
            candidates.add(h)

    # --- CVE IDs ---
    for m in _RE_CVE.finditer(text):
        candidates.add(m.group().upper())

    # --- MITRE ATT&CK technique IDs ---
    for m in _RE_MITRE.finditer(text):
        candidates.add(m.group())

    # --- Windows registry keys ---
    for m in _RE_REGKEY.finditer(text):
        # Trim trailing punctuation common in prose.
        key = m.group().rstrip(".,;:)\"' ")
        candidates.add(key)

    # --- PowerShell encoded blocks (prefix the b64 with a sentinel so the
    #     extractor consumer can route it without re-matching). ---
    for m in _RE_PS_ENCODED.finditer(text):
        b64 = m.group(1)
        candidates.add(f"ps_encoded:{b64}")

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
    """Apply :func:`enrich_alert_iocs` to every alert in *alerts*."""
    return [enrich_alert_iocs(alert) for alert in alerts]
