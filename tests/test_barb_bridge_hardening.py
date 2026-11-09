"""Hardening of the barb bridge: same-environment barb, neutral cwd, version gate.

barb <= 1.8.0 read ``./config.yaml`` from the current directory, so a file planted
where the analyst runs sift could downgrade barb's verdict. These tests never run
the real barb: subprocess-level tests swap the argv prefix for a fake script.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sift.enrichers import barb_bridge
from sift.enrichers.barb_bridge import BarbBridge, _call_barb_cli, barb_unavailable_reason

_VERSION = "sift.enrichers.barb_bridge._installed_barb_version"

_FAKE_BARB = """
import json, os, sys
print(json.dumps({
    "ioc": sys.argv[-1],
    "cwd": os.getcwd(),
    "entries": sorted(os.listdir(".")),
    "env_python": sorted(k for k in os.environ if k.startswith("PYTHON")),
    "home": os.environ.get("HOME"),
    "argv": sys.argv[1:],
}))
"""


@pytest.fixture
def fake_barb(tmp_path, monkeypatch):
    script = tmp_path / "fake_barb.py"
    script.write_text(_FAKE_BARB)
    monkeypatch.setattr(barb_bridge, "_barb_command", lambda: [sys.executable, str(script)])
    return script


def _ok_run() -> MagicMock:
    m = MagicMock()
    m.stdout = json.dumps({"verdict": "SAFE"})
    m.stderr = ""
    return m


class TestArgvAndSubprocessSettings:
    def test_argv_uses_current_interpreter_isolated_module(self):
        with patch("subprocess.run", return_value=_ok_run()) as run:
            _call_barb_cli("https://evil.ru/x")
        argv = run.call_args.args[0]
        assert argv[:4] == [sys.executable, "-I", "-m", "barb"]
        assert argv[4:] == ["analyze", "-o", "json", "-q", "--", "https://evil.ru/x"]

    def test_never_resolves_barb_via_path(self):
        with patch("shutil.which", side_effect=AssertionError("PATH lookup")) as which:
            with patch("subprocess.run", return_value=_ok_run()), patch(_VERSION, return_value="1.8.1"):
                BarbBridge().enrich(["https://evil.ru/x"])
        which.assert_not_called()

    def test_double_dash_precedes_dash_leading_ioc(self):
        with patch("subprocess.run", return_value=_ok_run()) as run:
            _call_barb_cli("-evil.example.com")
        argv = run.call_args.args[0]
        assert argv.index("--") == len(argv) - 2
        assert argv[-1] == "-evil.example.com"

    def test_timeout_and_cwd_and_env_are_set(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("subprocess.run", return_value=_ok_run()) as run:
            _call_barb_cli("evil.ru")
        kw = run.call_args.kwargs
        assert kw["timeout"] == 15
        assert kw["cwd"] is not None
        assert Path(kw["cwd"]).resolve() != tmp_path.resolve()
        assert "env" in kw

    def test_env_drops_python_vars_and_keeps_others(self, monkeypatch):
        monkeypatch.setenv("PYTHONPATH", "/evil")
        monkeypatch.setenv("PYTHONHOME", "/evil")
        monkeypatch.setenv("PYTHONSTARTUP", "/evil/s.py")
        monkeypatch.setenv("BARB_SOMETHING", "keep")
        env = barb_bridge._child_env()
        assert not [k for k in env if k.startswith("PYTHON")]
        assert env["BARB_SOMETHING"] == "keep"
        assert "PATH" in env


class TestPlantedFilesInAnalystCwd:
    def test_child_runs_in_empty_neutral_dir_not_analyst_cwd(self, fake_barb, tmp_path, monkeypatch):
        analyst = tmp_path / "analyst"
        analyst.mkdir()
        (analyst / "config.yaml").write_text("scoring:\n  threshold: 99\n")
        (analyst / ".env").write_text("BARB_API_KEY=planted\n")
        monkeypatch.chdir(analyst)
        out = _call_barb_cli("https://evil.ru/x")
        assert Path(out["cwd"]).resolve() != analyst.resolve()
        assert out["entries"] == []

    def test_python_env_not_inherited_by_child(self, fake_barb, monkeypatch):
        monkeypatch.setenv("PYTHONPATH", "/evil")
        monkeypatch.setenv("PYTHONSTARTUP", "/evil/s.py")
        out = _call_barb_cli("evil.ru")
        assert out["env_python"] == []

    def test_other_env_still_reaches_child(self, fake_barb, monkeypatch):
        monkeypatch.setenv("HOME", "/some/home")
        assert _call_barb_cli("evil.ru")["home"] == "/some/home"

    def test_double_dash_survives_real_subprocess(self, fake_barb):
        out = _call_barb_cli("-evil.example.com")
        assert out["argv"][-2:] == ["--", "-evil.example.com"]

    def test_each_call_gets_its_own_neutral_dir(self, fake_barb):
        a = _call_barb_cli("a.example.com")["cwd"]
        b = _call_barb_cli("b.example.com")["cwd"]
        assert a != b


class TestVersionGate:
    @pytest.mark.parametrize(
        ("version", "ok"),
        [
            ("1.8.1", True),
            ("1.8.2", True),
            ("1.9.0", True),
            ("2.0.0", True),
            ("1.10.0", True),
            ("1.8.0", False),
            ("1.0.0", False),
            ("0.9.9", False),
            ("1.8.1rc1", False),
            ("garbage", False),
            (None, False),
        ],
    )
    def test_reason_matrix(self, version, ok):
        assert (barb_unavailable_reason(version) is None) is ok

    @pytest.mark.parametrize("version", ["1.8.0", "1.0.0", None])
    def test_outdated_or_missing_skips_without_subprocess(self, version, caplog):
        with patch(_VERSION, return_value=version), patch("subprocess.run") as run:
            bridge = BarbBridge()
            with caplog.at_level(logging.WARNING, logger="sift.enrichers.barb_bridge"):
                results = bridge.enrich(["https://evil.ru/x", "185.220.101.47"])
        run.assert_not_called()
        assert bridge.available is False
        assert len(results) == 1
        assert results[0]["ioc"] == "https://evil.ru/x"
        assert "barb unavailable/outdated" in results[0]["error"]
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "barb enrichment skipped" in warnings[0].getMessage()

    def test_no_warning_when_nothing_to_enrich(self, caplog):
        with patch(_VERSION, return_value="1.0.0"):
            with caplog.at_level(logging.WARNING, logger="sift.enrichers.barb_bridge"):
                assert BarbBridge().enrich(["185.220.101.47"]) == []
        assert not caplog.records

    def test_current_version_is_available(self):
        with patch(_VERSION, return_value="1.8.1"):
            assert BarbBridge().available is True

    def test_probe_returns_none_when_child_fails(self):
        failed = MagicMock(returncode=1, stdout="", stderr="No module")
        with patch("subprocess.run", return_value=failed):
            assert barb_bridge._installed_barb_version.__wrapped__() is None

    def test_probe_runs_isolated_child_with_clean_env(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("PYTHONPATH", "/evil")
        ok = MagicMock(returncode=0, stdout="1.8.1\n", stderr="")
        with patch("subprocess.run", return_value=ok) as run:
            assert barb_bridge._installed_barb_version.__wrapped__() == "1.8.1"
        assert run.call_args.args[0][:3] == [sys.executable, "-I", "-c"]
        assert "PYTHONPATH" not in run.call_args.kwargs["env"]
        assert Path(run.call_args.kwargs["cwd"]).resolve() != tmp_path.resolve()

    def test_probe_ignores_pythonpath_shadow(self, tmp_path, monkeypatch):
        pytest.importorskip("barb")
        shadow = tmp_path / "shadow"
        dist = shadow / "barb_phish-99.0.0.dist-info"
        dist.mkdir(parents=True)
        (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: barb-phish\nVersion: 99.0.0\n")
        monkeypatch.setenv("PYTHONPATH", str(shadow))
        got = barb_bridge._installed_barb_version.__wrapped__()
        assert got is not None
        assert got != "99.0.0"


class TestDoctorReportsVersion:
    def test_pass_message_carries_version(self):
        from sift import doctor

        with patch(_VERSION, return_value="1.8.1"), patch.object(doctor, "_check_importable", return_value=True):
            r = doctor._check_enrich_barb()
        assert r.status is doctor.CheckStatus.PASS
        assert "1.8.1" in r.message

    def test_outdated_warns(self):
        from sift import doctor

        with patch(_VERSION, return_value="1.8.0"), patch.object(doctor, "_check_importable", return_value=True):
            r = doctor._check_enrich_barb()
        assert r.status is doctor.CheckStatus.WARN
        assert "1.8.0" in r.message


def test_module_does_not_import_shutil():
    assert "shutil" not in vars(barb_bridge)


def test_real_subprocess_module_runs_help_offline(tmp_path):
    """The real argv prefix resolves: ``python -I -m barb --help`` works in this env."""
    pytest.importorskip("barb")
    r = subprocess.run(
        [*barb_bridge._barb_command(), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,
        env={k: v for k, v in os.environ.items() if not k.startswith("PYTHON")},
    )
    assert r.returncode == 0
