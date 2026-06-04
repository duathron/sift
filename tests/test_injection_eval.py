"""The injection eval gate must hold on the committed corpus."""

from __future__ import annotations

from eval.run_injection_eval import _DEFAULT_MIN_PRECISION, _DEFAULT_MIN_RECALL, run


def test_injection_eval_meets_floors():
    result = run()
    assert result.tp + result.fn > 0, "corpus has no positive (injection) samples"
    assert result.precision >= _DEFAULT_MIN_PRECISION, f"benign alert flagged (FP): precision={result.precision}"
    assert result.recall >= _DEFAULT_MIN_RECALL, f"recall {result.recall} < floor {_DEFAULT_MIN_RECALL}"
