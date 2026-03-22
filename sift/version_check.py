"""PyPI version check with local caching."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from . import __version__

_CACHE_FILE = Path.home() / ".sift" / "version_check.json"
_PYPI_URL = "https://pypi.org/pypi/sift-triage/json"


def check_for_update(check_interval_hours: int = 24) -> Optional[str]:
    """Return the latest PyPI version string if newer than installed, else None.

    Results are cached for *check_interval_hours* to avoid hammering PyPI.
    Fails silently — never raises.
    """
    try:
        cache = _load_cache()
        now = time.time()
        interval = check_interval_hours * 3600

        if cache and (now - cache.get("checked_at", 0)) < interval:
            latest = cache.get("latest")
        else:
            import urllib.request

            with urllib.request.urlopen(_PYPI_URL, timeout=3) as resp:
                data = json.loads(resp.read())
            latest = data["info"]["version"]
            _save_cache({"checked_at": now, "latest": latest})

        if latest and latest != __version__:
            return latest
    except Exception:
        pass
    return None


def _load_cache() -> dict:
    try:
        if _CACHE_FILE.exists():
            return json.loads(_CACHE_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_cache(data: dict) -> None:
    try:
        _CACHE_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(data))
    except Exception:
        pass
