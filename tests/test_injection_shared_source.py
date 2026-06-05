"""G12 guard: sift's detector must delegate to the shared lib engine."""

from shipwright_kit.security.injection import (
    InjectionFinding as LibFinding,
)
from shipwright_kit.security.injection import (
    PromptInjectionDetector as LibDetector,
)

from sift.summarizers.injection_detector import InjectionFinding, PromptInjectionDetector


def test_finding_type_is_the_lib_type():
    assert InjectionFinding is LibFinding


def test_sift_detector_uses_lib_core():
    d = PromptInjectionDetector()
    assert isinstance(d._core, LibDetector)
