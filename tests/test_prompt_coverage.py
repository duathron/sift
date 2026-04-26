"""Tier-1 LLM prompt safety tests — prevent silent data loss in build_cluster_prompt().

Four guards:
  1.1  Severity coverage  — every severity in cluster.alerts appears in the prompt
  1.2  Alert-type coverage — all titles appear for ≤10 types; overflow count shown for >10
  1.3  Slice lint         — every [:N] literal in prompt.py carries a # SAFE-SLICE comment
  1.4  Realistic cluster  — 500 alerts, 20 types, mixed severity (the v1.0.16 scenario)

Background: v1.0.16 had a [:5] slice on alert types that silently buried CRITICAL events
(Credential Dumping, Lateral Movement) in large clusters.  These tests catch that class
of bug at the unit level before it ever reaches a release.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sift.config import SummarizeConfig
from sift.models import Alert, AlertSeverity, Cluster, ClusterPriority, TriageReport

from sift.summarizers.prompt import build_cluster_prompt

# Path to the file under guard
PROMPT_PY = Path(__file__).parent.parent / "sift" / "summarizers" / "prompt.py"

# _SHOW constant from prompt.py — keep in sync if it ever changes
_SHOW = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(title: str = "Generic Alert", severity: AlertSeverity = AlertSeverity.LOW) -> Alert:
    return Alert(id=str(uuid.uuid4()), title=title, severity=severity)


def make_cluster(alerts: list[Alert], label: str = "Test Cluster") -> Cluster:
    return Cluster(
        id=str(uuid.uuid4()),
        label=label,
        alerts=alerts,
        priority=ClusterPriority.HIGH,
        score=75.0,
        iocs=[],
    )


def make_report(clusters: list[Cluster]) -> TriageReport:
    return TriageReport(
        alerts_ingested=sum(len(c.alerts) for c in clusters),
        alerts_after_dedup=sum(len(c.alerts) for c in clusters),
        clusters=clusters,
        analyzed_at=datetime.now(timezone.utc),
    )


def default_config() -> SummarizeConfig:
    return SummarizeConfig()


def build_prompt(alerts: list[Alert]) -> str:
    return build_cluster_prompt(make_report([make_cluster(alerts)]), default_config())


# ---------------------------------------------------------------------------
# Tier 1.1 — Severity coverage
# ---------------------------------------------------------------------------

class TestSeverityCoverage:
    """Every severity present in a cluster's alerts must appear in the prompt.

    The v1.0.16 bug class: a slice or sort could place CRITICAL alerts past a
    cutoff and drop them silently.  The breakdown is severity-sorted descending,
    so CRITICAL is always first — but these tests make that guarantee explicit.
    """

    @pytest.mark.parametrize("target_sev", list(AlertSeverity))
    def test_minority_severity_not_dropped(self, target_sev: AlertSeverity):
        """One rare-severity alert type among 99 same-titled LOW alerts must survive into the prompt.

        Uses 2 distinct alert titles (≤ _SHOW=10), so both types always appear explicitly.
        Confirms severity label is present regardless of count dominance.
        """
        # 99 alerts, all same title → ONE distinct LOW type; plus one distinct target_sev type
        alerts = [make_alert("Noise Alert", AlertSeverity.LOW) for _ in range(99)]
        alerts.append(make_alert("Rare Signal", target_sev))
        prompt = build_prompt(alerts)
        assert target_sev.value in prompt, (
            f"Severity {target_sev.value!r} is present in the cluster but missing from the prompt. "
            "Check for unguarded slices in build_cluster_prompt()."
        )

    def test_critical_sorted_before_low_in_breakdown(self):
        """CRITICAL entry must appear before any LOW entry in the alert-type breakdown."""
        alerts = (
            [make_alert("Credential Dumping", AlertSeverity.CRITICAL)] +
            [make_alert(f"Low Noise {i}", AlertSeverity.LOW) for i in range(50)]
        )
        prompt = build_prompt(alerts)
        breakdown_start = prompt.find("Alert type breakdown")
        assert breakdown_start != -1, "Alert type breakdown section missing from prompt."
        first_critical = prompt.find("[CRITICAL]", breakdown_start)
        first_low = prompt.find("[LOW]", breakdown_start)
        assert first_critical != -1, "[CRITICAL] label missing from breakdown."
        assert first_low != -1, "[LOW] label missing from breakdown."
        assert first_critical < first_low, (
            "[CRITICAL] must appear before [LOW] in breakdown (sorted by severity descending)."
        )

    def test_all_five_severity_levels_appear_when_present(self):
        """Cluster with one alert of each severity → all five labels in prompt."""
        alerts = [
            make_alert("Critical Event", AlertSeverity.CRITICAL),
            make_alert("High Event", AlertSeverity.HIGH),
            make_alert("Medium Event", AlertSeverity.MEDIUM),
            make_alert("Low Event", AlertSeverity.LOW),
            make_alert("Info Event", AlertSeverity.INFO),
        ]
        prompt = build_prompt(alerts)
        for sev in AlertSeverity:
            assert sev.value in prompt, (
                f"Severity {sev.value!r} missing from prompt despite being present in cluster."
            )

    def test_critical_not_dropped_when_exactly_at_show_limit(self):
        """_SHOW distinct types with CRITICAL at position 0 — CRITICAL must still appear."""
        alerts = [make_alert("Critical Type", AlertSeverity.CRITICAL)]
        # Fill remaining _SHOW-1 slots with different LOW types
        for i in range(_SHOW - 1):
            alerts.append(make_alert(f"Low Type {i}", AlertSeverity.LOW))
        prompt = build_prompt(alerts)
        assert "CRITICAL" in prompt

    def test_critical_not_dropped_when_one_over_show_limit(self):
        """_SHOW + 1 distinct types — CRITICAL (highest severity) must still appear."""
        alerts = [make_alert("Critical Type", AlertSeverity.CRITICAL)]
        for i in range(_SHOW):  # _SHOW more LOW types → total = _SHOW + 1 distinct types
            alerts.append(make_alert(f"Low Type {i}", AlertSeverity.LOW))
        prompt = build_prompt(alerts)
        assert "CRITICAL" in prompt, (
            "CRITICAL type was pushed out of prompt by LOW types. "
            "Sorting-by-severity-descending must keep CRITICAL in first _SHOW slots."
        )


# ---------------------------------------------------------------------------
# Tier 1.2 — Alert-type coverage
# ---------------------------------------------------------------------------

class TestAlertTypeCoverage:
    """Distinct alert titles must not be silently truncated from the prompt."""

    def test_all_types_explicit_when_count_equals_show_limit(self):
        """Exactly _SHOW distinct types → all titles appear explicitly."""
        types = [f"Attack Type {i}" for i in range(_SHOW)]
        alerts = [make_alert(t, AlertSeverity.MEDIUM) for t in types]
        prompt = build_prompt(alerts)
        for t in types:
            assert t in prompt, (
                f"Alert type {t!r} missing from prompt (exactly {_SHOW} types — all must appear)."
            )

    def test_overflow_count_shown_when_types_exceed_show_limit(self):
        """_SHOW + 1 distinct types → an overflow line with explicit count must be present."""
        types = [f"Attack Type {i}" for i in range(_SHOW + 1)]
        alerts = [make_alert(t, AlertSeverity.LOW) for t in types]
        prompt = build_prompt(alerts)
        assert "more type" in prompt, (
            "Overflow types must be counted in the prompt, not silently dropped. "
            "Add a '… (N more type(s))' line."
        )

    def test_highest_severity_types_shown_when_overflow_occurs(self):
        """When >_SHOW types, the _SHOW highest-severity ones must appear explicitly."""
        # 5 CRITICAL + (_SHOW) LOW = _SHOW + 5 types total
        # sorted: 5 CRITICAL first → all 5 must be within first _SHOW
        critical_types = [f"Critical Attack {i}" for i in range(5)]
        low_types = [f"Low Noise {i}" for i in range(_SHOW)]
        alerts = (
            [make_alert(t, AlertSeverity.CRITICAL) for t in critical_types] +
            [make_alert(t, AlertSeverity.LOW) for t in low_types]
        )
        prompt = build_prompt(alerts)
        for t in critical_types:
            assert t in prompt, (
                f"CRITICAL type {t!r} missing from prompt. "
                "HIGH-severity types must not be pushed out by LOW types."
            )

    def test_overflow_count_is_arithmetically_correct(self):
        """'… (N more type(s))' N must match actual overflow count."""
        n_types = _SHOW + 3  # 3 overflow
        types = [f"Type {i}" for i in range(n_types)]
        alerts = [make_alert(t, AlertSeverity.MEDIUM) for t in types]
        prompt = build_prompt(alerts)
        assert "3 more type" in prompt, (
            f"Expected '3 more type(s)' for {n_types} types with _SHOW={_SHOW}, "
            "but got a different count."
        )

    def test_ioc_overflow_suffix_shown(self):
        """6 IOCs with [:5] preview → suffix must report remaining count."""
        cluster = Cluster(
            id=str(uuid.uuid4()),
            label="IOC Cluster",
            alerts=[make_alert("IOC Alert", AlertSeverity.HIGH)],
            priority=ClusterPriority.HIGH,
            score=80.0,
            iocs=[f"10.0.0.{i}" for i in range(6)],
        )
        prompt = build_cluster_prompt(make_report([cluster]), default_config())
        assert "+1 more" in prompt, "IOC overflow suffix missing — [:5] slice must report remaining count."


# ---------------------------------------------------------------------------
# Tier 1.3 — Slice lint
# ---------------------------------------------------------------------------

class TestSliceLint:
    """Guard against unguarded [:N] slices that can silently drop high-severity data."""

    _SLICE_RE = re.compile(r"\[:\d+\]")
    _SAFE_MARKER = "# SAFE-SLICE"

    def test_no_unguarded_numeric_slices_in_prompt_py(self):
        """Every [:N] literal in sift/summarizers/prompt.py must carry a # SAFE-SLICE comment."""
        assert PROMPT_PY.exists(), f"prompt.py not found at {PROMPT_PY}"
        violations: list[str] = []
        for lineno, line in enumerate(PROMPT_PY.read_text().splitlines(), start=1):
            if self._SLICE_RE.search(line) and self._SAFE_MARKER not in line:
                violations.append(f"  Line {lineno}: {line.rstrip()}")
        assert not violations, (
            "Unguarded [:N] slice(s) in sift/summarizers/prompt.py.\n"
            "Add '# SAFE-SLICE: <reason>' to justify each slice, or rewrite without truncation:\n"
            + "\n".join(violations)
        )


# ---------------------------------------------------------------------------
# Tier 1.4 — Realistic large-cluster fixture (the v1.0.16 scenario)
# ---------------------------------------------------------------------------

# 20 realistic SOC alert types, severity-distributed as seen in production
# Counts sum to exactly 500 alerts:
#   3 CRITICAL types  × 25  =  75  (15 %)
#   3 HIGH types      × 50  = 150  (30 %)
#   4 MEDIUM types    × 25  = 100  (20 %)
#   5 LOW types       × 15  =  75  (15 %)
#   5 INFO types      × 20  = 100  (20 %)

_REALISTIC_TYPES: list[tuple[str, AlertSeverity, int]] = [
    # title                                  severity               count
    ("Credential Dumping Detected",          AlertSeverity.CRITICAL,   25),
    ("Lateral Movement via SMB",             AlertSeverity.CRITICAL,   25),
    ("Ransomware File Encryption",           AlertSeverity.CRITICAL,   25),
    ("Outbound Data Transfer Detected",       AlertSeverity.HIGH,       50),
    ("Privilege Escalation Attempt",         AlertSeverity.HIGH,       50),
    ("C2 Beacon Detected",                   AlertSeverity.HIGH,       50),
    ("Suspicious PowerShell Execution",      AlertSeverity.MEDIUM,     25),
    ("Brute Force Login Attempt",            AlertSeverity.MEDIUM,     25),
    ("Unusual Network Scan",                 AlertSeverity.MEDIUM,     25),
    ("DNS Query to Known Malicious Domain",  AlertSeverity.MEDIUM,     25),
    ("File Downloaded from Untrusted Source",AlertSeverity.LOW,        15),
    ("Firewall Rule Modified",               AlertSeverity.LOW,        15),
    ("New Admin Account Created",            AlertSeverity.LOW,        15),
    ("Service Installed on Host",            AlertSeverity.LOW,        15),
    ("USB Device Inserted",                  AlertSeverity.LOW,        15),
    ("Failed Login Attempt",                 AlertSeverity.INFO,       20),
    ("Port Scan from Internal Host",         AlertSeverity.INFO,       20),
    ("Antivirus Definition Update",          AlertSeverity.INFO,       20),
    ("Scheduled Task Created",               AlertSeverity.INFO,       20),
    ("Network Policy Change Detected",        AlertSeverity.INFO,       20),
]

_CRITICAL_TITLES = [t for t, s, _ in _REALISTIC_TYPES if s == AlertSeverity.CRITICAL]
_HIGH_TITLES = [t for t, s, _ in _REALISTIC_TYPES if s == AlertSeverity.HIGH]


def _build_realistic_large_cluster() -> Cluster:
    """Build 500-alert, 20-type, mixed-severity cluster deterministically."""
    alerts: list[Alert] = []
    for title, sev, count in _REALISTIC_TYPES:
        alerts.extend(make_alert(title, sev) for _ in range(count))
    assert len(alerts) == 500, f"Expected 500 alerts, got {len(alerts)}"
    return Cluster(
        id="realistic-large-cluster-001",
        label="Realistic Large Cluster",
        alerts=alerts,
        priority=ClusterPriority.CRITICAL,
        score=92.0,
        iocs=[f"10.0.{i}.{j}" for i in range(5) for j in range(1, 11)],  # 50 IOCs
    )


class TestRealisticLargeCluster:
    """Prompt quality on the v1.0.16 scenario: 500 alerts, 20 types, mixed severity.

    With _SHOW=10 and severity-sorted descending, the first 10 types shown are:
    3 CRITICAL + 3 HIGH + 4 MEDIUM = 10 (exact fit).
    5 LOW + 5 INFO = 10 overflow types → '… (10 more type(s))' line.
    """

    @pytest.fixture(scope="class")
    def cluster(self) -> Cluster:
        return _build_realistic_large_cluster()

    @pytest.fixture(scope="class")
    def prompt(self, cluster: Cluster) -> str:
        return build_cluster_prompt(make_report([cluster]), default_config())

    # --- Basic sanity ---

    def test_prompt_is_non_empty(self, prompt: str):
        assert len(prompt) > 500

    def test_cluster_label_present(self, prompt: str):
        assert "Realistic Large Cluster" in prompt

    def test_alert_count_present(self, prompt: str):
        assert "500" in prompt

    # --- Severity coverage ---

    def test_critical_severity_label_present(self, prompt: str):
        assert "[CRITICAL]" in prompt

    def test_high_severity_label_present(self, prompt: str):
        assert "[HIGH]" in prompt

    def test_medium_severity_label_present(self, prompt: str):
        assert "[MEDIUM]" in prompt

    # --- Critical type coverage (the v1.0.16 failure scenario) ---

    @pytest.mark.parametrize("title", _CRITICAL_TITLES)
    def test_critical_type_appears_in_prompt(self, prompt: str, title: str):
        """Each CRITICAL alert type must be explicitly named in the prompt."""
        assert title in prompt, (
            f"CRITICAL type {title!r} missing from 500-alert cluster prompt. "
            "Severity-sorted breakdown must place CRITICAL types first (within _SHOW=10)."
        )

    @pytest.mark.parametrize("title", _HIGH_TITLES)
    def test_high_type_appears_in_prompt(self, prompt: str, title: str):
        """Each HIGH alert type must be explicitly named in the prompt."""
        assert title in prompt, (
            f"HIGH type {title!r} missing from 500-alert cluster prompt."
        )

    # --- Overflow handling ---

    def test_overflow_line_shows_ten_more_types(self, prompt: str):
        """20 types − _SHOW=10 shown = 10 overflow → '… (10 more type(s))'."""
        assert "10 more type" in prompt, (
            "Expected '10 more type(s)' overflow line for 20-type cluster with _SHOW=10."
        )

    def test_breakdown_header_present(self, prompt: str):
        assert "Alert type breakdown" in prompt

    def test_distinct_type_count_in_header(self, prompt: str):
        """Header must report '20 distinct type(s)'."""
        assert "20 distinct type" in prompt

    # --- IOC overflow ---

    def test_ioc_overflow_suffix_present(self, prompt: str):
        """50 IOCs with [:5] preview → '+45 more' suffix must appear."""
        assert "+45 more" in prompt, "IOC overflow suffix '+45 more' missing for 50-IOC cluster."

    # --- No-regression: CRITICAL before LOW in text order ---

    def test_critical_entry_shown_not_in_overflow(self, prompt: str):
        """CRITICAL entry must appear in the explicit breakdown rows, not in overflow.

        With 20 types and _SHOW=10, the breakdown shows: 3 CRITICAL + 3 HIGH + 4 MEDIUM.
        5 LOW + 5 INFO fall into overflow.  [CRITICAL] must appear before '… (10 more'.
        """
        breakdown_start = prompt.find("Alert type breakdown")
        assert breakdown_start != -1
        first_critical_pos = prompt.find("[CRITICAL]", breakdown_start)
        overflow_pos = prompt.find("more type", breakdown_start)
        assert first_critical_pos != -1, "[CRITICAL] label missing from breakdown."
        assert overflow_pos != -1, "Overflow line missing from breakdown."
        assert first_critical_pos < overflow_pos, (
            "[CRITICAL] entry must appear in explicit rows, not in the overflow count."
        )
