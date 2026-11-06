"""Cache key for stored triage reports.

The key covers everything that changes the report that gets stored, not only the
input bytes: the per-file input identity, the options that shape the report, the
summarize settings, the enrichment mode, the tool and security-engine versions,
and the non-secret config sections. Secrets (API key, ticketing credentials)
never enter the key material.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from shipwright_kit.security.injection import INJECTION_PATTERNS_VERSION
from shipwright_kit.security.render import SAFE_RENDER_VERSION

from . import __version__

# Bump to invalidate every previously stored entry.
CACHE_SCHEMA = 3

# Non-secret endpoint settings that change which model answers (never an API key).
_ENDPOINT_ENV = ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL")

_CFG_SECTIONS = {"clustering", "scoring", "summarize", "redaction", "injection", "enrich"}


def _cfg_subset(cfg) -> dict[str, Any]:
    """Allow-listed config sections, with the API key removed."""
    data = cfg.model_dump(include=_CFG_SECTIONS)
    data.get("summarize", {}).pop("api_key", None)
    return data


def _key_material(input_identity: list[dict], *, options: dict, cfg) -> dict[str, Any]:
    return {
        "v": CACHE_SCHEMA,
        "sift": __version__,
        "kit": [SAFE_RENDER_VERSION, INJECTION_PATTERNS_VERSION],
        "input": input_identity,
        "opts": options,
        "cfg": _cfg_subset(cfg),
        "env": {name: os.environ.get(name) for name in _ENDPOINT_ENV},
    }


def build_cache_key(input_identity: list[dict], *, options: dict, cfg) -> str:
    """Return the sha256 hex key for one triage run."""
    material = json.dumps(_key_material(input_identity, options=options, cfg=cfg), sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
