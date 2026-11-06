"""Per-component pins for the triage cache key, and the cache's own hardening.

Every CLI test runs with the cache ON (hermetic dir from ``tests/conftest.py``) and
asserts the literal "Cache hit" / "Cache miss" line.
"""

from __future__ import annotations

import json
import sqlite3
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

import sift.cache_key as ck
import sift.main as main_mod
from sift.cache_key import _key_material, build_cache_key
from sift.config import AppConfig
from sift.main import app

FIXTURES = Path(__file__).parent / "fixtures"
MIXED = str(FIXTURES / "mixed.json")
LATERAL = str(FIXTURES / "lateral_movement.json")

runner = CliRunner()


def _run(*args: str, **kw):
    return runner.invoke(app, ["triage", *args], **kw)


def _db(tmp_path: Path) -> Path:
    return tmp_path / "cache" / "alerts.db"


def _sql(tmp_path: Path, query: str, *params):
    con = sqlite3.connect(_db(tmp_path))
    try:
        rows = con.execute(query, params).fetchall()
        con.commit()
        return rows
    finally:
        con.close()


def _row_count(tmp_path: Path) -> int:
    if not _db(tmp_path).exists():
        return 0
    return _sql(tmp_path, "SELECT COUNT(*) FROM cache_entries")[0][0]


def _clean_exit(r) -> bool:
    return r.exception is None or isinstance(r.exception, SystemExit)


# --- 1: external enrichment is external state ------------------------------------------

_URL_ALERT = [
    {
        "id": "u1",
        "title": "Beacon to http://malware-site.net/payload",
        "description": "callback http://malware-site.net/payload",
        "severity": "critical",
        "host": "h1",
        "timestamp": "2026-04-20T10:00:00Z",
    }
]


def test_external_enrichment_is_never_replayed(tmp_path, monkeypatch):
    src = tmp_path / "url.json"
    src.write_text(json.dumps(_URL_ALERT))
    empty = tmp_path / "empty_bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    r1 = _run(str(src), "-f", "json", "--enrich", "barb", "-y")
    assert "STUBVERDICT" not in r1.stdout

    stub_dir = tmp_path / "stub_bin"
    stub_dir.mkdir()
    stub = stub_dir / "barb"
    stub.write_text('#!/bin/sh\necho \'{"ioc": "x", "verdict": "STUBVERDICT"}\'\n')
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(stub_dir))
    r2 = _run(str(src), "-f", "json", "--enrich", "barb", "-y")
    assert "Cache hit" not in r2.stderr
    assert "STUBVERDICT" in r2.stdout
    assert _row_count(tmp_path) == 0


# --- 2: LLM endpoint env vars ----------------------------------------------------------


@pytest.mark.parametrize("var", ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"])
def test_llm_base_url_env_changes_key(monkeypatch, var):
    ident = [{"name": "a.json", "size": 1, "sha256": "ab" * 32}]
    monkeypatch.setenv(var, "https://one.invalid")
    k1 = build_cache_key(ident, options={}, cfg=AppConfig())
    monkeypatch.setenv(var, "https://two.invalid")
    assert build_cache_key(ident, options={}, cfg=AppConfig()) != k1


def test_llm_base_url_env_misses_on_cli(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://one.invalid")
    assert "Cache miss" in _run(MIXED, "-f", "json").stderr
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://two.invalid")
    assert "Cache miss" in _run(MIXED, "-f", "json").stderr


def test_api_key_env_never_in_key_material(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-CANARY")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-CANARY")
    monkeypatch.setenv("SIFT_LLM_KEY", "sk-sift-CANARY")
    material = json.dumps(_key_material([], options={}, cfg=AppConfig()), default=str)
    assert "CANARY" not in material


# --- 3: a degraded summary is not cached -----------------------------------------------


def test_degraded_template_summary_is_not_cached(tmp_path, monkeypatch):
    def boom(provider, cfg, **kw):
        raise RuntimeError("template exploded")

    monkeypatch.setattr(main_mod, "_build_summarizer", boom)
    r1 = _run(MIXED, "-f", "json", "--summarize", "--provider", "template")
    assert "Summarization failed" in r1.stderr
    assert _row_count(tmp_path) == 0
    r2 = _run(MIXED, "-f", "json", "--summarize", "--provider", "template")
    assert "Cache miss" in r2.stderr


# --- 4: bad and future cache entries are misses ----------------------------------------


def test_bad_cache_entry_is_a_miss_and_invalidated(tmp_path):
    _run(MIXED, "-f", "json")
    _sql(tmp_path, "UPDATE cache_entries SET result_json = ?", '{"bogus":1}')
    r2 = _run(MIXED, "-f", "json")
    assert _clean_exit(r2)
    assert "Cache miss" in r2.stderr
    assert "clusters" in json.loads(r2.stdout)
    assert "Cache hit" in _run(MIXED, "-f", "json").stderr


def test_future_dated_cache_entry_is_ignored(tmp_path):
    _run(MIXED, "-f", "json")
    _sql(tmp_path, "UPDATE cache_entries SET created_at = ?", "2999-01-01T00:00:00+00:00")
    r2 = _run(MIXED, "-f", "json")
    assert "Cache miss" in r2.stderr
    assert "Cache hit" in _run(MIXED, "-f", "json").stderr


# --- 5: hash-then-read gap -------------------------------------------------------------


def test_input_changed_between_hash_and_parse_is_not_stored(tmp_path, monkeypatch):
    src = tmp_path / "in.json"
    src.write_text(Path(MIXED).read_text())
    real = Path.read_bytes

    def swap_then_read(self):
        if self.name == "in.json":
            self.write_text(Path(LATERAL).read_text())
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", swap_then_read)
    r = _run(str(src), "-f", "json")
    assert _clean_exit(r)
    assert _row_count(tmp_path) == 0


# --- 6: one CLI test per key component -------------------------------------------------

_SUM = ("--summarize", "--provider", "mock")


@pytest.mark.parametrize(
    ("base", "variant"),
    [
        ((), ("--no-dedup",)),
        ((), ("--drop-raw",)),
        ((), ("--chunk-size", "2")),
        ((), ("--enrich", "local")),
        ((), ("--no-llm",)),
        ((), ("-s",)),
        (_SUM, ("--summarize", "--provider", "template")),
        (_SUM, (*_SUM, "--no-llm")),
    ],
    ids=["no_dedup", "drop_raw", "chunk_size", "enrich_local", "no_llm", "summarize", "provider", "no_llm_summarize"],
)
def test_each_option_is_part_of_the_key(base, variant):
    r1 = _run(MIXED, "-f", "json", *base)
    assert "Cache miss" in r1.stderr
    r2 = _run(MIXED, "-f", "json", *variant)
    assert "Cache miss" in r2.stderr
    assert "Cache hit" not in r2.stderr


def test_effective_redact_includes_config_fields(tmp_path, monkeypatch):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("redaction:\n  fields: [user]\n")
    seen: list[dict] = []
    real = ck.build_cache_key

    def spy(identity, *, options, cfg):
        seen.append(options)
        return real(identity, options=options, cfg=cfg)

    monkeypatch.setattr(ck, "build_cache_key", spy)
    _run(MIXED, "-f", "json", "--config", str(cfg_file))
    assert seen[0]["redact"] == ["user"]


# --- 7: input identity through main.py -------------------------------------------------


def _alerts(title: str) -> str:
    return json.dumps(
        [{"id": "a1", "title": title, "severity": "high", "host": "h1", "timestamp": "2026-04-20T10:00:00Z"}]
    )


def test_same_name_same_size_different_bytes_misses(tmp_path):
    f = tmp_path / "in.json"
    f.write_text(_alerts("Alpha"))
    assert "Cache miss" in _run(str(f), "-f", "json").stderr
    assert "Cache hit" in _run(str(f), "-f", "json").stderr
    f.write_text(_alerts("Bravo"))
    assert f.stat().st_size == len(_alerts("Alpha"))
    assert "Cache miss" in _run(str(f), "-f", "json").stderr


def test_stdin_twice_misses_then_hits():
    text = _alerts("Alpha")
    assert "Cache miss" in _run("-", "-f", "json", input=text).stderr
    assert "Cache hit" in _run("-", "-f", "json", input=text).stderr


def test_same_bytes_stdin_vs_named_file_misses(tmp_path):
    f = tmp_path / "in.json"
    f.write_text(_alerts("Alpha"))
    assert "Cache miss" in _run(str(f), "-f", "json").stderr
    assert "Cache miss" in _run("-", "-f", "json", input=_alerts("Alpha")).stderr


def test_same_bytes_different_file_name_misses(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(_alerts("Alpha"))
    b.write_text(_alerts("Alpha"))
    assert "Cache miss" in _run(str(a), "-f", "json").stderr
    assert "Cache miss" in _run(str(b), "-f", "json").stderr


def test_key_changes_with_sha256_only():
    one = [{"name": "a.json", "size": 10, "sha256": "ab" * 32}]
    two = [{"name": "a.json", "size": 10, "sha256": "cd" * 32}]
    assert build_cache_key(one, options={}, cfg=AppConfig()) != build_cache_key(two, options={}, cfg=AppConfig())


# --- 8: config sections ----------------------------------------------------------------


def _set(path: str, value):
    def apply(cfg: AppConfig) -> AppConfig:
        *parents, leaf = path.split(".")
        node = cfg
        for p in parents:
            node = getattr(node, p)
        setattr(node, leaf, value)
        return cfg

    return apply


@pytest.mark.parametrize(
    "mutate",
    [
        _set("scoring.thresholds.high", 51),
        _set("redaction.redact_raw", True),
        _set("injection.enabled", False),
        _set("enrich.consent_given", True),
        _set("clustering.max_cluster_size", 7),
        _set("summarize.temperature", 0.9),
    ],
    ids=["scoring", "redaction", "injection", "enrich", "clustering", "summarize"],
)
def test_each_config_section_changes_the_key(mutate):
    ident = [{"name": "a.json", "size": 1, "sha256": "ab" * 32}]
    base = build_cache_key(ident, options={}, cfg=AppConfig())
    assert build_cache_key(ident, options={}, cfg=mutate(AppConfig())) != base


def test_cache_schema_is_part_of_the_key(monkeypatch):
    ident = [{"name": "a.json", "size": 1, "sha256": "ab" * 32}]
    base = build_cache_key(ident, options={}, cfg=AppConfig())
    monkeypatch.setattr(ck, "CACHE_SCHEMA", ck.CACHE_SCHEMA + 1)
    assert build_cache_key(ident, options={}, cfg=AppConfig()) != base


# --- 9: no secret in the stored payload ------------------------------------------------


def test_stored_cache_holds_no_secret(tmp_path, monkeypatch):
    for var, val in {
        "SIFT_LLM_KEY": "sk-CANARY-llm",
        "SIFT_THEHIVE_TOKEN": "tok-CANARY-hive",
        "SIFT_JIRA_TOKEN": "tok-CANARY-jira",
        "ANTHROPIC_API_KEY": "sk-CANARY-ant",
    }.items():
        monkeypatch.setenv(var, val)
    r = _run(MIXED, "-f", "json", "--summarize", "--provider", "mock")
    assert "Cache miss" in r.stderr
    assert _row_count(tmp_path) == 1
    blob = b"".join(p.read_bytes() for p in _db(tmp_path).parent.glob("alerts.db*"))
    assert b"CANARY" not in blob
