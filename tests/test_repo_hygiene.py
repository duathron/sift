"""Repository hygiene guards."""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def test_dotenv_is_gitignored() -> None:
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    for name in (".env", ".env.local", "sub/.env"):
        proc = subprocess.run(
            ["git", "check-ignore", "-q", name],
            cwd=REPO,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, f"{name} is not gitignored"
