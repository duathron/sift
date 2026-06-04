"""Guard: sift eval --json built against shipwright_kit eval schema; a bump fails CI."""

from __future__ import annotations


def test_eval_schema_version_pinned():
    from shipwright_kit.eval import EVAL_SCHEMA_VERSION

    assert EVAL_SCHEMA_VERSION == 1
