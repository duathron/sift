"""BarbBridge — enrichment bridge to barb (heuristic phishing URL analyzer).

barb is called via subprocess to avoid internal API coupling. The bridge
filters to URL/domain IOCs and parses the JSON output of `barb analyze`.

Hardening (barb <= 1.8.0 read ``./config.yaml`` from the current directory, so
a planted file could downgrade a verdict):

* barb runs from *sift's own environment* (``sys.executable -I -m barb``), never
  from whatever ``barb`` is first on ``PATH``.
* the installed ``barb-phish`` must be >= 1.8.1; below that (or missing) the
  enrichment is skipped with a warning and a marked error result. There is no
  fallback to ``PATH``.
* the child runs in a fresh, empty temporary directory (a stdlib
  ``tempfile.TemporaryDirectory``, cleaned up by the stdlib), not in the
  analyst's working directory.
* the child's environment drops every ``PYTHON*`` variable (``PYTHONPATH``,
  ``PYTHONHOME``, ``PYTHONSTARTUP``, ...); ``-I`` ignores them as well and also
  keeps the working directory and user site out of ``sys.path``. All other
  variables (HOME, ``BARB_*``, proxies) are passed through on purpose.
"""

from __future__ import annotations

import importlib.metadata
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import tempfile

logger = logging.getLogger(__name__)

# First barb-phish release that no longer reads ./config.yaml from the CWD.
_MIN_BARB_VERSION = (1, 8, 1)
_MIN_BARB_VERSION_TEXT = "1.8.1"
_UPGRADE_HINT = "pip install -U 'sift-triage[enrich]'"


def _installed_barb_version() -> str | None:
    """Return the barb-phish version installed in this environment, or None."""
    try:
        return importlib.metadata.version("barb-phish")
    except importlib.metadata.PackageNotFoundError:
        return None


def barb_unavailable_reason(version: str | None) -> str | None:
    """Return why *version* is unusable, or None if it meets the minimum.

    Pre-release / unparsable versions are treated as outdated (fail closed).
    """
    if version is None:
        return f"barb-phish is not installed ({_UPGRADE_HINT})"
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if m is None or tuple(int(g) for g in m.groups()) < _MIN_BARB_VERSION:
        return f"barb-phish {version} is older than {_MIN_BARB_VERSION_TEXT} ({_UPGRADE_HINT})"
    return None


def _barb_command() -> list[str]:
    """argv prefix that runs barb from this interpreter's environment."""
    return [sys.executable, "-I", "-m", "barb"]


def _child_env() -> dict[str, str]:
    """Environment for the barb child: inherited minus every ``PYTHON*`` var."""
    return {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}


class BarbBridge:
    """Enrichment bridge for barb (barb-phish on PyPI).

    Uses the subprocess approach to call the barb CLI so sift has no
    hard import dependency on barb internals.
    """

    def __init__(self) -> None:
        self.version: str | None = _installed_barb_version()
        self.unavailable_reason: str | None = barb_unavailable_reason(self.version)
        self.available: bool = self.unavailable_reason is None

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
        if ioc.lower().startswith(("http://", "https://", "ftp://", "hxxp://", "hxxps://")):
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
        url_iocs = [i for i in iocs if self.can_enrich(i)]
        if not self.available:
            if url_iocs:
                logger.warning("barb enrichment skipped: %s", self.unavailable_reason)
            return [{"ioc": ioc, "error": f"barb unavailable/outdated: {self.unavailable_reason}"} for ioc in url_iocs]

        results: list[dict] = []
        for ioc in url_iocs:
            results.append(_call_barb_cli(ioc))
        return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _call_barb_cli(ioc: str) -> dict:
    try:
        with tempfile.TemporaryDirectory(prefix="sift-barb-") as neutral_cwd:
            result = subprocess.run(
                [*_barb_command(), "analyze", "-o", "json", "-q", "--", ioc],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=neutral_cwd,
                env=_child_env(),
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
    return len(stripped) in (32, 40, 64, 128) and all(c in "0123456789abcdefABCDEF" for c in stripped)


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
    if upper.startswith(("HKLM\\", "HKCU\\", "HKCR\\", "HKU\\", "HKCC\\", "HKEY_")):
        return True
    if v.startswith("ps_encoded:"):
        return True
    if v.count(":") == 2:
        parts = v.split(":")
        if parts[0].isdigit() and len(parts[1]) >= 3 and len(parts[2]) >= 3:
            return True
    if upper.startswith("T1") and len(v) in (70, 72) and all(c in "0123456789ABCDEFabcdef" for c in v[2:]):
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
_NON_IOC_TLDS = frozenset(
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

_FILE_EXTENSIONS = frozenset(
    {
        ".exe",
        ".dll",
        ".sys",
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".log",
        ".ldb",
        ".sst",
        ".tmp",
        ".mca",
        ".inf",
        ".msi",
        ".jar",
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".iso",
        ".img",
        ".py",
        ".sh",
        ".rb",
        ".pl",
        ".php",
    }
)
