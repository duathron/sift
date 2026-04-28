"""BarbBridge — enrichment bridge to barb (heuristic phishing URL analyzer).

barb is called via subprocess to avoid internal API coupling. The bridge
filters to URL/domain IOCs and parses the JSON output of `barb analyze`.
"""

import json
import shutil
import subprocess


class BarbBridge:
    """Enrichment bridge for barb (barb-phish on PyPI).

    Uses the subprocess approach to call the barb CLI so sift has no
    hard import dependency on barb internals.
    """

    def __init__(self) -> None:
        self.available: bool = shutil.which("barb") is not None

    @property
    def name(self) -> str:
        return "barb"

    def can_enrich(self, ioc: str) -> bool:
        """Return True for URLs (http/https/ftp) and bare domain-like strings."""
        ioc = ioc.strip()
        if ioc.lower().startswith(("http://", "https://", "ftp://",
                                   "hxxp://", "hxxps://")):
            return True
        # Bare domain heuristic: contains at least one dot, no spaces,
        # not a plain IP (handled by vex), not a hash.
        if (
            "." in ioc
            and " " not in ioc
            and not _looks_like_ip(ioc)
            and not _looks_like_hash(ioc)
        ):
            return True
        return False

    def enrich(self, iocs: list[str]) -> list[dict]:
        """Enrich URL/domain IOCs via barb CLI. Returns one dict per IOC."""
        if not self.available:
            return [{"ioc": ioc, "error": "barb not installed"} for ioc in iocs]

        url_iocs = [i for i in iocs if self.can_enrich(i)]
        results: list[dict] = []
        for ioc in url_iocs:
            results.append(_call_barb_cli(ioc))
        return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _call_barb_cli(ioc: str) -> dict:
    barb_bin = shutil.which("barb")
    if not barb_bin:
        return {"ioc": ioc, "error": "barb not found in PATH"}
    try:
        result = subprocess.run(
            [barb_bin, "analyze", "-o", "json", "-q", "--", ioc],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
        return {"ioc": ioc, "error": result.stderr.strip() or "empty output"}
    except subprocess.TimeoutExpired:
        return {"ioc": ioc, "error": "barb timed out after 15s"}
    except json.JSONDecodeError as exc:
        return {"ioc": ioc, "error": f"barb JSON parse error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"ioc": ioc, "error": str(exc)}


def _looks_like_ip(value: str) -> bool:
    import ipaddress
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
