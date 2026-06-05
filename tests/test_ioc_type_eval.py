"""Tests for the per-type IOC classification-accuracy gate."""

from __future__ import annotations

from pathlib import Path

from eval.run_ioc_type_eval import run


def test_corpus_is_fully_correct():
    """Every IOC in the shipped corpus classifies to its exact expected type."""
    result = run()
    assert result.total == 20
    assert result.correct == 20
    assert result.accuracy == 1.0
    assert result.misses == []


def test_all_sixteen_types_covered():
    result = run()
    assert len(result.per_type) == 16
    expected_types = {
        "ip",
        "domain",
        "url",
        "email",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
        "hash_sha512",
        "ssdeep",
        "tlsh",
        "jarm",
        "ps_encoded",
        "cve",
        "mitre_technique",
        "registry_key",
        "filename",
    }
    assert set(result.per_type) == expected_types


def test_gate_has_teeth(tmp_path: Path):
    """A deliberately mislabeled row is reported as a miss (gate would fail)."""
    bad = tmp_path / "bad_type_corpus.csv"
    bad.write_text("text,type\n8.8.8.8,domain\n")  # an IP labeled as domain
    result = run(bad)
    assert result.correct == 0
    assert result.accuracy == 0.0
    assert result.misses == [("8.8.8.8", "domain", "ip")]
    # confusion is recorded under the expected type
    assert result.per_type["domain"].confusions == {"ip": 1}
