"""VexBridge — enrichment bridge to vex (VirusTotal IOC enrichment tool).

vex is called via subprocess to avoid internal API coupling. The bridge
handles IPs, domains, file hashes, and URLs — everything except email
addresses.
"""

import json
import shutil
import subprocess


class VexBridge:
    """Enrichment bridge for vex (vex-ioc on PyPI).

    Uses the subprocess approach to call the vex CLI so sift has no
    hard import dependency on vex internals.
    """

    def __init__(self) -> None:
        self.available: bool = shutil.which("vex") is not None

    @property
    def name(self) -> str:
        return "vex"

    def can_enrich(self, ioc: str) -> bool:
        """Return True for IPs, domains, hashes, and URLs — not email addresses."""
        ioc = ioc.strip()
        # Exclude email addresses
        if _looks_like_email(ioc):
            return False
        # Accept hashes
        if _looks_like_hash(ioc):
            return True
        # Accept IPs (v4 and v6)
        if _looks_like_ip(ioc):
            return True
        # Accept URLs
        if ioc.lower().startswith(("http://", "https://", "ftp://",
                                   "hxxp://", "hxxps://")):
            return True
        # Accept bare domains (contains dot, no spaces)
        if "." in ioc and " " not in ioc:
            return True
        return False

    def enrich(self, iocs: list[str]) -> list[dict]:
        """Enrich IOCs via vex CLI. Returns one dict per IOC."""
        if not self.available:
            return [{"ioc": ioc, "error": "vex not installed"} for ioc in iocs]

        results: list[dict] = []
        for ioc in iocs:
            results.append(_call_vex_cli(ioc))
        return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _call_vex_cli(ioc: str) -> dict:
    vex_bin = shutil.which("vex")
    if not vex_bin:
        return {"ioc": ioc, "error": "vex not found in PATH"}
    try:
        result = subprocess.run(
            [vex_bin, "triage", "--", ioc, "-o", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
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
    import ipaddress
    try:
        ipaddress.ip_address(value.split("/")[0].split("%")[0])
        return True
    except ValueError:
        return False


def _looks_like_hash(value: str) -> bool:
    """MD5 (32), SHA-1 (40), SHA-256 (64) hex strings."""
    stripped = value.strip()
    return len(stripped) in (32, 40, 64) and all(
        c in "0123456789abcdefABCDEF" for c in stripped
    )
