"""Regression: a cache hit must still run --ticket post-processing (Pass-1 bug).

Before the fix, sift rendered the cached report and exited BEFORE ticketing, so
`sift triage <cached-input> --ticket X` silently created no ticket. Unlike
test_main_ticket_integration.py (which disables caching), this test runs with
caching ENABLED to exercise the cache-hit path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sift.main import app

runner = CliRunner()

_ALERTS = json.dumps(
    [
        {
            "id": "x1",
            "title": "Credential Dumping",
            "severity": "critical",
            "host": "dc01",
            "timestamp": "2026-04-20T10:00:00Z",
            "category": "credential_access",
        }
    ]
)


@pytest.fixture(autouse=True)
def _isolated_app_dir(tmp_path, monkeypatch):
    # Caching ENABLED (default), but isolated to a throwaway app dir.
    app_dir = tmp_path / "sift_home"
    app_dir.mkdir()
    monkeypatch.setattr("sift.config._APP_DIR", app_dir)


def test_cache_hit_still_creates_ticket(tmp_path: Path):
    alerts = tmp_path / "a.json"
    alerts.write_text(_ALERTS)
    out1, out2 = tmp_path / "t1.json", tmp_path / "t2.json"

    # 1st run → cache MISS (populates cache) + ticket
    r1 = runner.invoke(
        app,
        ["triage", str(alerts), "--ticket", "dry-run", "--ticket-output", str(out1), "-f", "json", "-q"],
    )
    assert r1.exit_code in (0, 1)
    assert out1.exists(), f"miss-run ticket not created: {r1.output}"

    # 2nd run → cache HIT (same input) — ticket MUST still be created
    r2 = runner.invoke(
        app,
        ["triage", str(alerts), "--ticket", "dry-run", "--ticket-output", str(out2), "-f", "json", "-q"],
    )
    assert r2.exit_code in (0, 1)
    assert out2.exists(), f"cache-hit ticket not created — cache swallowed ticketing: {r2.output}"
