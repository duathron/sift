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
        - Synthetic / framework-reference IOC types (CVE, MITRE, registry,
          PowerShell encoded blocks, ssdeep, TLSH)
        """
        ioc = ioc.strip()
        # Exclude framework / synthetic IOC types — barb only resolves
        # URLs and bare domains.
        if _is_non_enrichable_type(ioc):
            return False
        # Exclude markdown links (raw [text](url) from Sysmon fields)
        if ioc.startswith("["):
            return False
        # Accept URLs *first* — URLs may legitimately contain ``@`` in
        # userinfo (``http://user:pass@host/...``), so the URL check has
        # to run before the bare ``@`` rejection or those URLs are lost.
        if ioc.lower().startswith(("http://", "https://", "ftp://",
                                   "hxxp://", "hxxps://")):
            return True
        # Exclude email addresses (after URL acceptance).
        if "@" in ioc:
            return False
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
    """MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128) hex strings."""
    stripped = value.strip()
    return len(stripped) in (32, 40, 64, 128) and all(
        c in "0123456789abcdefABCDEF" for c in stripped
    )


def _is_non_enrichable_type(value: str) -> bool:
    """Return True if *value* is a synthetic / framework-reference IOC type
    that barb (URL/domain enrichment) does not support.

    Covers: CVE IDs, MITRE ATT&CK technique IDs, Windows registry keys,
    PowerShell encoded sentinel values, ssdeep / TLSH fingerprints.
    """
    if not value:
        return False
    v = value.strip()
    upper = v.upper()
    if upper.startswith("CVE-"):
        return True
    if (
        len(v) >= 5
        and v[0] == "T"
        and v[1:5].isdigit()
        and (len(v) == 5 or (len(v) == 9 and v[5] == "." and v[6:].isdigit()))
    ):
        return True
    if upper.startswith(("HKLM\\", "HKCU\\", "HKCR\\", "HKU\\", "HKCC\\",
                         "HKEY_")):
        return True
    if v.startswith("ps_encoded:"):
        return True
    if v.count(":") == 2:
        parts = v.split(":")
        if (
            parts[0].isdigit()
            and len(parts[1]) >= 3
            and len(parts[2]) >= 3
        ):
            return True
    if upper.startswith("T1") and len(v) in (70, 72) and all(
        c in "0123456789ABCDEFabcdef" for c in v[2:]
    ):
        return True
    return False


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
