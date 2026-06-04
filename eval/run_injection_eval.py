"""Detection-quality gate for sift's prompt-injection detector.

Binary eval (injection / clean) against a labeled corpus, delegating the
confusion tally + metrics + gate to shipwright.eval (the framework's shared eval
runtime; sift is its 2nd consumer after barb).

Usage:
    python -m eval.run_injection_eval
    python -m eval.run_injection_eval --json
    python -m eval.run_injection_eval --min-precision 1.0 --min-recall 0.95
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from shipwright.eval.corpus import load_corpus
from shipwright.eval.harness import EvalGateError, evaluate, gate
from shipwright.eval.metrics import EvalResult

from sift.models import Alert
from sift.summarizers.injection_detector import scan_alert

_DEFAULT_CORPUS = Path(__file__).parent / "corpus" / "injection_corpus.csv"
_DEFAULT_MIN_PRECISION = 1.0  # v1.0.16 lesson: no false positives on benign SOC alerts
_DEFAULT_MIN_RECALL = 0.95  # measured recall 1.0 on 16 positives (2026-06-04); 0.95 = round-down headroom


def _predict(text: str) -> str:
    alert = Alert(id="eval", title="Alert", description=text)
    return "injection" if scan_alert(alert) else "clean"


def run(corpus_path: Optional[Path] = None) -> EvalResult:
    corpus = load_corpus(corpus_path or _DEFAULT_CORPUS, input_col="text")
    return evaluate(
        _predict,
        corpus,
        positive_pred=lambda p: p == "injection",
        positive_expected=lambda label: label == "injection",
    )


def main(argv: Optional[list[str]] = None) -> None:
    ap = argparse.ArgumentParser(prog="eval.run_injection_eval")
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
