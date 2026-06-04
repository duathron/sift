"""Property/fuzz tests at sift's untrusted-input parse boundary.

Contract: every parser must survive ARBITRARY input — never raise an unhandled
exception, always return the declared type. Catches the liberal-parse crash class
(the vex/barb Pass-1b lesson) before it reaches a release.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from sift.models import Alert
from sift.normalizers.csv_normalizer import CSVNormalizer
from sift.normalizers.generic import GenericNormalizer
from sift.normalizers.splunk import SplunkNormalizer
from sift.pipeline.ioc_extractor import classify_severity_hint, detect_ioc_type, extract_iocs
from sift.summarizers.injection_detector import scan_alert

# Nasty-but-valid text: control/format/surrogate chars, unicode, injection-ish, large.
_text = st.text(alphabet=st.characters(exclude_categories=()), max_size=2000)
_json_ish = st.one_of(
    _text,
    st.builds(lambda s: "{" + s, _text),
    st.builds(lambda s: "[" + s + "]", _text),
    st.builds(lambda s: '{"results":[' + s + "]}", _text),
    st.just(""),
    st.just("\x00\x00"),
)

_NORMALIZERS = [CSVNormalizer(), GenericNormalizer(), SplunkNormalizer()]


@settings(max_examples=200)
@given(raw=_json_ish)
def test_normalizers_never_crash(raw):
    for n in _NORMALIZERS:
        # can_handle and normalize must NEVER raise; normalize returns list[Alert].
        assert isinstance(n.can_handle(raw), bool)
        out = n.normalize(raw)
        assert isinstance(out, list)
        assert all(isinstance(a, Alert) for a in out)


@settings(max_examples=300)
@given(s=_text)
def test_ioc_extractor_never_crashes(s):
    iocs = extract_iocs(s)
    assert isinstance(iocs, list)
    assert all(isinstance(i, str) for i in iocs)
    for i in iocs:
        assert isinstance(detect_ioc_type(i), str)  # classification total
        classify_severity_hint(i)  # may return str|None, must not raise
    # also fuzz the classifiers directly on arbitrary strings
    assert isinstance(detect_ioc_type(s), str)


# Alerts whose text fields carry arbitrary (possibly injection-shaped) content.
_alert = st.builds(
    Alert,
    id=st.text(min_size=1, max_size=40),
    title=_text,
    description=st.one_of(st.none(), _text),
    source=st.one_of(st.none(), _text),
    user=st.one_of(st.none(), _text),
    host=st.one_of(st.none(), _text),
    category=st.one_of(st.none(), _text),
    raw=st.dictionaries(st.text(max_size=20), st.one_of(_text, st.integers(), st.none()), max_size=8),
)


@settings(max_examples=200)
@given(alert=_alert)
def test_injection_detector_never_crashes(alert):
    findings = scan_alert(alert)
    assert isinstance(findings, list)
