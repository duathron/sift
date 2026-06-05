"""Per-type classification-accuracy gate for sift's IOC classifier.

Unlike run_ioc_eval (binary: ioc / benign via detect_ioc_type != "unknown"),
this asserts each IOC classifies to its EXACT type — so a regression that turns
a sha256 into a sha1, or a jarm into an unknown, fails the gate even though the
binary gate would still pass. Multiclass, so it does NOT use shipwright_kit.eval's
binary confusion harness; it loads the labeled corpus and computes accuracy +
a per-type breakdown directly.

Usage:
    python -m eval.run_ioc_type_eval [--json] [--min-accuracy A]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from shipwright_kit.eval.corpus import load_corpus

from sift.pipeline.ioc_extractor import detect_ioc_type

_DEFAULT_CORPUS = Path(__file__).parent / "corpus" / "ioc_type_corpus.csv"
# Operator-controlled corpus over a deterministic classifier: any misclassification
# is a real regression, so the floor is exact. Measured 1.0 on all 16 types (2026-06-05).
_DEFAULT_MIN_ACCURACY = 1.0


@dataclass
class TypeStat:
    total: int = 0
    correct: int = 0
    # expected_type -> count of each wrong actual label observed
    confusions: dict[str, int] = field(default_factory=lambda: defaultdict(int))


@dataclass
class TypeEvalResult:
    total: int
    correct: int
    per_type: dict[str, TypeStat]
    misses: list[tuple[str, str, str]]  # (text, expected, actual)

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0


def run(corpus_path: Optional[Path] = None) -> TypeEvalResult:
    corpus = load_corpus(corpus_path or _DEFAULT_CORPUS, input_col="text", label_col="type")
    per_type: dict[str, TypeStat] = defaultdict(TypeStat)
    misses: list[tuple[str, str, str]] = []
    correct = 0

    for sample in corpus:
        expected = sample.label
        actual = detect_ioc_type(sample.input)
        stat = per_type[expected]
        stat.total += 1
        if actual == expected:
            stat.correct += 1
            correct += 1
        else:
            stat.confusions[actual] += 1
            misses.append((sample.input, expected, actual))

    return TypeEvalResult(
        total=len(corpus),
        correct=correct,
        per_type=dict(per_type),
        misses=misses,
    )


def _summary(result: TypeEvalResult) -> dict:
    return {
        "total": result.total,
        "correct": result.correct,
        "accuracy": round(result.accuracy, 4),
        "types_covered": len(result.per_type),
        "per_type": {
            t: {
                "total": s.total,
                "correct": s.correct,
                "confusions": dict(s.confusions),
            }
            for t, s in sorted(result.per_type.items())
        },
        "misses": [{"text": text, "expected": exp, "actual": act} for text, exp, act in result.misses],
    }


def main(argv: Optional[list[str]] = None) -> None:
    ap = argparse.ArgumentParser(prog="eval.run_ioc_type_eval")
    ap.add_argument("--corpus", type=Path, default=None)
    ap.add_argument("--json", dest="as_json", action="store_true")
    ap.add_argument("--min-accuracy", type=float, default=_DEFAULT_MIN_ACCURACY)
    args = ap.parse_args(argv)

    result = run(args.corpus)
    summary = _summary(result)

    if args.as_json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"{'total':18} {result.total}")
        print(f"{'correct':18} {result.correct}")
        print(f"{'accuracy':18} {summary['accuracy']}")
        print(f"{'types_covered':18} {summary['types_covered']}")
        for t, s in sorted(result.per_type.items()):
            mark = "" if s.correct == s.total else f"  <-- {dict(s.confusions)}"
            print(f"  {t:18} {s.correct}/{s.total}{mark}")

    if result.accuracy < args.min_accuracy or result.misses:
        print(
            f"GATE FAILED: per-type accuracy {result.accuracy:.4f} < {args.min_accuracy} "
            f"({len(result.misses)} misclassification(s): {result.misses})",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
