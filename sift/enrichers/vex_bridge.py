"""VexBridge — enrichment bridge to vex (VirusTotal IOC enrichment tool).

vex is called via subprocess to avoid internal API coupling. The bridge
handles IPs, domains, file hashes, and URLs — everything except email
addresses, filenames, markdown links, and private/reserved IPs.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess


class VexBridge:
    """Enrichment bridge for vex (vex-ioc on PyPI).

    Uses the subprocess approach to call the vex CLI so sift has no
    hard import dependency on vex internals.
    """

    def __init__(self) -> None:
        self._vex_bin: str | None = shutil.which("vex")
        self.available: bool = self._vex_bin is not None

    @property
    def name(self) -> str:
        return "vex"

    def can_enrich(self, ioc: str) -> bool:
        """Return True for public IPs, domains, hashes, and URLs.

        Excluded:
        - Email addresses (contain @)
        - Markdown links (start with [)
        - Filenames (known extensions: .exe, .dll, .log, etc.)
        - Private/reserved/loopback IP addresses
        - Domains with non-routable TLDs (.local, .internal, .example, etc.)
        """
        ioc = ioc.strip()
        # Exclude markdown links (raw [text](url) from Sysmon fields)
        if ioc.startswith("["):
            return False
        # Exclude email addresses
        if _looks_like_email(ioc):
            return False
        # Accept hashes (MD5/SHA1/SHA256)
        if _looks_like_hash(ioc):
            return True
        # Accept public IPs only (exclude private, reserved, loopback)
        if _looks_like_ip(ioc):
            return not _is_private_or_reserved_ip(ioc)
        # Accept URLs (any scheme — TLD filtering not applied to full URLs)
        if ioc.lower().startswith(("http://", "https://", "ftp://",
                                   "hxxp://", "hxxps://")):
            return True
        # Exclude filenames (common extensions that are not domains)
        if _looks_like_filename(ioc):
            return False
        # Accept bare domains: has dot, no spaces, non-internal TLD
        if "." in ioc and " " not in ioc:
            tld = ioc.rsplit(".", 1)[-1].lower()
            return tld not in _NON_IOC_TLDS
        return False

    def enrich(self, iocs: list[str]) -> list[dict]:
        """Enrich IOCs via vex CLI. Returns one dict per IOC."""
        if not self.available:
            return [{"ioc": ioc, "error": "vex not installed"} for ioc in iocs]

        results: list[dict] = []
        for ioc in iocs:
            results.append(_call_vex_cli(ioc, self._vex_bin))
        return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _call_vex_cli(ioc: str, vex_bin: str | None = None) -> dict:
    bin_path = vex_bin or shutil.which("vex")
    if not bin_path:
        return {"ioc": ioc, "error": "vex not found in PATH"}
    try:
        result = subprocess.run(
            [bin_path, "triage", "-o", "json", "--", ioc],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.stdout.strip():
            parsed = json.loads(result.stdout)
            # vex returns [] on HTTP errors or unsupported IOC types
            if isinstance(parsed, list):
                if not parsed:
                    return {"ioc": ioc, "error": "vex: no results (IOC type unsupported or HTTP error)"}
                first = parsed[0]
                return first if isinstance(first, dict) else {"ioc": ioc, "error": "vex: unexpected output format"}
            if not isinstance(parsed, dict):
                return {"ioc": ioc, "error": f"vex: unexpected output type {type(parsed).__name__}"}
            return parsed
        return {"ioc": ioc, "error": result.stderr.strip() or "empty output"}
    except subprocess.TimeoutExpired:
        return {"ioc": ioc, "error": "vex timed out after 30s"}
    except json.JSONDecodeError as exc:
        return {"ioc": ioc, "error": f"vex JSON parse error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"ioc": ioc, "error": str(exc)}


def _looks_like_email(value: str) -> bool:
    return "@" in value and "." in value.split("@")[-1]


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("/")[0].split("%")[0])
        return True
    except ValueError:
        return False


def _is_private_or_reserved_ip(value: str) -> bool:
    """Return True if IP is private, loopback, link-local, or unspecified."""
    try:
        ip = ipaddress.ip_address(value.split("/")[0].split("%")[0])
        if ip.version == 4:
            return any(ip in net for net in _PRIVATE_NETS_V4)
        # IPv6: check IPv4-mapped addresses against the IPv4 private nets
        if ip.ipv4_mapped is not None:
            return any(ip.ipv4_mapped in net for net in _PRIVATE_NETS_V4)
        # Pure IPv6: filter loopback, link-local, unspecified, documentation range,
        # and the ::/8 reserved prefix (catches ::ffff:3 and similar compressed forms
        # that ipv4_mapped does not recognise).
        return (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or ip in _DOC_NET_V6
            or ip in _RESERVED_PREFIX_V6
        )
    except ValueError:
        return False


def _looks_like_hash(value: str) -> bool:
    """MD5 (32), SHA-1 (40), SHA-256 (64) hex strings."""
    stripped = value.strip()
    return len(stripped) in (32, 40, 64) and all(
        c in "0123456789abcdefABCDEF" for c in stripped
    )


def _looks_like_filename(value: str) -> bool:
    """Return True if value looks like a filename rather than a domain."""
    if "." not in value:
        return False
    ext = "." + value.rsplit(".", 1)[-1].lower()
    return ext in _FILE_EXTENSIONS


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PRIVATE_NETS_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space (RFC 6598)
    ipaddress.ip_network("0.0.0.0/8"),        # unspecified / reserved
]

_DOC_NET_V6 = ipaddress.ip_network("2001:db8::/32")        # documentation range (RFC 3849)
_RESERVED_PREFIX_V6 = ipaddress.ip_network("::/8")         # all-zero first-byte IPv6 (reserved / special)

# TLDs that indicate non-routable / internal domains — mirror ioc_extractor._NON_IOC_TLDS
_NON_IOC_TLDS = frozenset({
    "local", "internal", "corp", "test", "example", "invalid",
    "localhost", "lan", "home", "intranet", "localdomain", "domain", "arpa",
})

_FILE_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".log", ".ldb", ".sst", ".tmp", ".mca", ".inf", ".msi", ".jar",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img",
    ".py", ".sh", ".rb", ".pl", ".php",
})
