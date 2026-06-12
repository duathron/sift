"""Tests for S2a: eager --version flag on the sift app callback.

TDD — written before production code.

Covers:
  - `sift --version` exits 0 and prints version string
  - `sift version` subcommand still works (kept for backward compat)
  - Both print the same version string
"""

from __future__ import annotations

import re

from typer.testing import CliRunner

from sift import __version__
from sift.main import app

_runner = CliRunner()


class TestVersionFlag:
    """--version eager flag on the app callback."""

    def test_version_flag_exits_zero(self):
        result = _runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_prints_version_string(self):
        result = _runner.invoke(app, ["--version"])
        assert __version__ in result.output

    def test_version_flag_output_contains_sift(self):
        result = _runner.invoke(app, ["--version"])
        assert "sift" in result.output.lower()

    def test_version_flag_output_matches_pattern(self):
        """Version output looks like 'sift v1.2.3' or 'sift 1.2.3'."""
        result = _runner.invoke(app, ["--version"])
        assert re.search(r"sift.+\d+\.\d+", result.output)


class TestVersionSubcommand:
    """version subcommand must still work after adding the --version flag."""

    def test_version_subcommand_exits_zero(self):
        result = _runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_version_subcommand_prints_version_string(self):
        result = _runner.invoke(app, ["version"])
        assert __version__ in result.output


class TestVersionConsistency:
    """--version flag and version subcommand print the same version."""

    def test_flag_and_subcommand_same_output(self):
        flag_result = _runner.invoke(app, ["--version"])
        sub_result = _runner.invoke(app, ["version"])
        # Both outputs must contain the same version string
        assert __version__ in flag_result.output
        assert __version__ in sub_result.output
