"""The shipwright-kit floor must include the v2 security engines (0.12.1)."""

import re
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_kit_lower_bound_is_at_least_0_12_1() -> None:
    deps = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["dependencies"]
    kit = [d for d in deps if d.replace(" ", "").lower().startswith("shipwright-kit")]
    assert len(kit) == 1, kit
    match = re.search(r">=\s*(\d+)\.(\d+)\.(\d+)", kit[0])
    assert match, f"no lower bound in {kit[0]!r}"
    assert tuple(int(g) for g in match.groups()) >= (0, 12, 1)
