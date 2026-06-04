"""The IOC-classifier eval gate must hold on the committed corpus."""

from __future__ import annotations

from eval.run_ioc_eval import _DEFAULT_MIN_PRECISION, _DEFAULT_MIN_RECALL, run


def test_ioc_eval_meets_floors():
    result = run()
    assert result.tp + result.fn > 0, "corpus has no IOC positives"
    assert result.precision >= _DEFAULT_MIN_PRECISION, f"benign classified as IOC (FP): precision={result.precision}"
    assert result.recall >= _DEFAULT_MIN_RECALL, f"recall {result.recall} < floor {_DEFAULT_MIN_RECALL}"
