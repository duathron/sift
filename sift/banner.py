"""ASCII art banner for sift."""

from __future__ import annotations

import sys

from . import __version__

_BANNER = r"""
  ____ ___ _____ _____
 / ___|_ _|  ___|_   _|
 \___ \| || |_    | |
  ___) | ||  _|   | |
 |____/___|_|     |_|
"""

_INFO = " v{version} | by Christian Huhn | Alert Triage Summarizer"
_LINE = " " + "─" * 52


def show_banner(
    *,
    quiet: bool = False,
    update_check_enabled: bool = True,
    check_interval_hours: int = 24,
) -> None:
    """Print the sift banner to stderr.

    Suppressed when quiet=True or stdout is not a TTY (piped output).
    """
    if quiet:
        return
    if not sys.stdout.isatty():
        return

    print(_BANNER, file=sys.stderr)
    print(_INFO.format(version=__version__), file=sys.stderr)
    print(_LINE, file=sys.stderr)

    if update_check_enabled:
        try:
            from .version_check import check_for_update

            latest = check_for_update(check_interval_hours)
            if latest:
                print(f"  Update available: {__version__} -> {latest}", file=sys.stderr)
                print("  pip install --upgrade sift-triage", file=sys.stderr)
        except Exception:
            pass
