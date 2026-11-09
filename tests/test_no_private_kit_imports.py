"""sift must only use shipwright_kit's public API: no underscore-prefixed imports."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "sift"


def test_sift_imports_no_underscore_name_from_shipwright_kit():
    offenders = []
    for path in sorted(ROOT.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), str(path))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "shipwright_kit":
                offenders += [f"{path}:{node.lineno} {a.name}" for a in node.names if a.name.startswith("_")]
    assert not offenders, offenders


def test_sift_no_longer_references_private_fold():
    hits = [str(p) for p in sorted(ROOT.rglob("*.py")) if "_fold" in p.read_text(encoding="utf-8")]
    assert not hits, hits
