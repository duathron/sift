"""Detection-quality gate for sift's IOC classifier (detect_ioc_type).

Binary eval (ioc / benign) against a labeled corpus, delegating to shipwright_kit.eval.
A string is an IOC iff detect_ioc_type(s) != "unknown". The corpus covers all 16
detected IOC types as positives + non-IOC strings as negatives.

Usage:
    python -m eval.run_ioc_eval [--json] [--min-precision P] [--min-recall R]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from shipwright_kit.eval.corpus import load_corpus
from shipwright_kit.eval.harness import EvalGateError, evaluate, gate
from shipwright_kit.eval.metrics import EvalResult

from sift.pipeline.ioc_extractor import detect_ioc_type

_DEFAULT_CORPUS = Path(__file__).parent / "corpus" / "ioc_classification_corpus.csv"
_DEFAULT_MIN_PRECISION = 1.0  # no benign string may be classified as an IOC
_DEFAULT_MIN_RECALL = 0.95  # measured recall 1.0 on 20 positives / all 16 types (2026-06-04); round-down headroom


def _predict(text: str) -> str:
    return "ioc" if detect_ioc_type(text) != "unknown" else "benign"


def run(corpus_path: Optional[Path] = None) -> EvalResult:
    corpus = load_corpus(corpus_path or _DEFAULT_CORPUS, input_col="text")
    return evaluate(
        _predict,
        corpus,
        positive_pred=lambda p: p == "ioc",
        positive_expected=lambda label: label == "ioc",
    )


def main(argv: Optional[list[str]] = None) -> None:
    ap = argparse.ArgumentParser(prog="eval.run_ioc_eval")
    ap.add_argument("--corpus", type=Path, default=None)
    ap.add_argument("--json", dest="as_json", action="store_true")
    ap.add_argument("--min-precision", type=float, default=_DEFAULT_MIN_PRECISION)
    ap.add_argument("--min-recall", type=float, default=_DEFAULT_MIN_RECALL)
    args = ap.parse_args(argv)

    result = run(args.corpus)
    summary = {
        "tp": result.tp,
        "fp": result.fp,
        "tn": result.tn,
        "fn": result.fn,
        "errors": result.errors,
        "precision": round(result.precision, 4),
        "recall": round(result.recall, 4),
        "f1": round(result.f1, 4),
        "accuracy": round(result.accuracy, 4),
        "false_positive_rate": round(result.false_positive_rate, 4),
    }
    if args.as_json:
        print(json.dumps(summary, indent=2))
    else:
        for k, v in summary.items():
            print(f"{k:20} {v}")

    try:
        gate(result, min_precision=args.min_precision, min_recall=args.min_recall)
    except EvalGateError as exc:
        print(f"GATE FAILED: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
