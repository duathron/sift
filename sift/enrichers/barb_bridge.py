"""BarbBridge — enrichment bridge to barb (heuristic phishing URL analyzer).

barb is called via subprocess to avoid internal API coupling. The bridge
filters to URL/domain IOCs and parses the JSON output of `barb analyze`.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess


class BarbBridge:
    """Enrichment bridge for barb (barb-phish on PyPI).

    Uses the subprocess approach to call the barb CLI so sift has no
    hard import dependency on barb internals.
    """

    def __init__(self) -> None:
        self._barb_bin: str | None = shutil.which("barb")
        self.available: bool = self._barb_bin is not None

    @property
    def name(self) -> str:
        return "barb"

    def can_enrich(self, ioc: str) -> bool:
        """Return True for URLs (http/https/ftp) and bare domain-like strings.

        Excluded:
        - Markdown links (start with [)
        - Email addresses (contain @)
        - Plain IP addresses (handled by vex)
        - File hashes (handled by vex)
        - Filenames (known extensions: .exe, .dll, .log, etc.)
        - Domains with non-routable TLDs (.local, .internal, .example, etc.)
        """
        ioc = ioc.strip()
        # Exclude markdown links (raw [text](url) from Sysmon fields)
        if ioc.startswith("["):
            return False
        # Exclude email addresses
        if "@" in ioc:
            return False
        # Accept URLs (http/https/ftp)
        if ioc.lower().startswith(("http://", "https://", "ftp://",
                                   "hxxp://", "hxxps://")):
            return True
        # Bare domain heuristic: contains at least one dot, no spaces,
        # not a plain IP, not a hash, not a filename, non-internal TLD.
        if (
            "." in ioc
            and " " not in ioc
            and not _looks_like_ip(ioc)
            and not _looks_like_hash(ioc)
            and not _looks_like_filename(ioc)
        ):
            tld = ioc.rsplit(".", 1)[-1].lower()
            return tld not in _NON_IOC_TLDS
        return False

    def enrich(self, iocs: list[str]) -> list[dict]:
        """Enrich URL/domain IOCs via barb CLI. Returns one dict per IOC."""
        if not self.available:
            return [{"ioc": ioc, "error": "barb not installed"} for ioc in iocs]

        url_iocs = [i for i in iocs if self.can_enrich(i)]
        results: list[dict] = []
        for ioc in url_iocs:
            results.append(_call_barb_cli(ioc, self._barb_bin))
        return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _call_barb_cli(ioc: str, barb_bin: str | None = None) -> dict:
    bin_path = barb_bin or shutil.which("barb")
    if not bin_path:
        return {"ioc": ioc, "error": "barb not found in PATH"}
    try:
        result = subprocess.run(
            [bin_path, "analyze", "-o", "json", "-q", "--", ioc],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.stdout.strip():
            parsed = json.loads(result.stdout)
            if not isinstance(parsed, dict):
                return {"ioc": ioc, "error": f"barb: unexpected output type {type(parsed).__name__}"}
            return parsed
        return {"ioc": ioc, "error": result.stderr.strip() or "empty output"}
    except subprocess.TimeoutExpired:
        return {"ioc": ioc, "error": "barb timed out after 15s"}
    except json.JSONDecodeError as exc:
        return {"ioc": ioc, "error": f"barb JSON parse error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"ioc": ioc, "error": str(exc)}


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("/")[0])
        return True
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
