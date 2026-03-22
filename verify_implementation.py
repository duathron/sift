#!/usr/bin/env python3
"""
Verification script for sift v0.5.0 implementation.

This script validates:
1. Config has PromptInjectionConfig
2. Main.py has --validate-only flag
3. Doctor.py has LLM schema validation check
4. E2E test file exists with 8+ tests
5. Version bumped to 0.5.0
6. CHANGELOG.md updated

Run: python3 verify_implementation.py
"""

import sys
from pathlib import Path

def check_config_injection():
    """Verify PromptInjectionConfig in config.py."""
    config_path = Path("sift/config.py")
    content = config_path.read_text()

    checks = [
        ("PromptInjectionConfig class exists", "class PromptInjectionConfig" in content),
        ("enabled field exists", "enabled: bool = True" in content),
        ("whitelist_patterns field exists", "whitelist_patterns: list[str]" in content),
        ("injection field in AppConfig", "injection: PromptInjectionConfig" in content),
    ]

    print("\n=== sift/config.py ===")
    all_pass = True
    for name, result in checks:
        status = "✓" if result else "✗"
        print(f"  {status} {name}")
        if not result:
            all_pass = False

    return all_pass


def check_main_validate_only():
    """Verify --validate-only flag in main.py."""
    main_path = Path("sift/main.py")
    content = main_path.read_text()

    checks = [
        ("validate_only parameter exists", "validate_only:" in content),
        ("--validate-only option defined", '"--validate-only"' in content),
        ("validate_only logic present", "if validate_only:" in content),
    ]

    print("\n=== sift/main.py ===")
    all_pass = True
    for name, result in checks:
        status = "✓" if result else "✗"
        print(f"  {status} {name}")
        if not result:
            all_pass = False

    return all_pass


def check_doctor_validation():
    """Verify LLM schema validation check in doctor.py."""
    doctor_path = Path("sift/doctor.py")
    content = doctor_path.read_text()

    checks = [
        ("_check_llm_schema_validation function exists", "_check_llm_schema_validation" in content),
        ("Schema validation check in run_checks", "_check_llm_schema_validation()" in content),
    ]

    print("\n=== sift/doctor.py ===")
    all_pass = True
    for name, result in checks:
        status = "✓" if result else "✗"
        print(f"  {status} {name}")
        if not result:
            all_pass = False

    return all_pass


def check_e2e_tests():
    """Verify E2E test file exists with tests."""
    test_path = Path("tests/test_e2e_validation.py")

    if not test_path.exists():
        print("\n=== tests/test_e2e_validation.py ===")
        print("  ✗ Test file does not exist")
        return False

    content = test_path.read_text()

    # Count test classes
    test_classes = content.count("class Test")
    test_methods = content.count("def test_")

    checks = [
        ("File exists", True),
        ("Has test classes", test_classes >= 8),
        ("Has test methods", test_methods >= 8),
        ("MockSummarizer imported", "MockSummarizer" in content),
        ("PromptInjectionDetector imported", "PromptInjectionDetector" in content),
        ("SummaryValidator imported", "SummaryValidator" in content),
    ]

    print("\n=== tests/test_e2e_validation.py ===")
    all_pass = True
    for name, result in checks:
        status = "✓" if result else "✗"
        print(f"  {status} {name} ({test_classes} classes, {test_methods} methods)")
        if not result:
            all_pass = False

    return all_pass


def check_version():
    """Verify version bumped to 0.5.0."""
    checks = {}

    # Check __init__.py
    init_path = Path("sift/__init__.py")
    init_content = init_path.read_text()
    checks["__init__.py"] = '0.5.0' in init_content

    # Check pyproject.toml
    pyproject_path = Path("pyproject.toml")
    pyproject_content = pyproject_path.read_text()
    checks["pyproject.toml"] = 'version = "0.5.0"' in pyproject_content

    print("\n=== Version Bump to 0.5.0 ===")
    all_pass = True
    for file, result in checks.items():
        status = "✓" if result else "✗"
        print(f"  {status} {file}")
        if not result:
            all_pass = False

    return all_pass


def check_changelog():
    """Verify CHANGELOG.md updated."""
    changelog_path = Path("CHANGELOG.md")
    content = changelog_path.read_text()

    checks = [
        ("v0.5.0 section exists", "## [0.5.0]" in content),
        ("Validation Layer mentioned", "Validation Layer" in content),
        ("Prompt Injection Detection mentioned", "Prompt Injection Detection" in content),
        ("MockSummarizer mentioned", "MockSummarizer" in content),
        ("E2E Test Suite mentioned", "E2E Test Suite" in content),
        ("--validate-only mentioned", "--validate-only" in content),
    ]

    print("\n=== CHANGELOG.md ===")
    all_pass = True
    for name, result in checks:
        status = "✓" if result else "✗"
        print(f"  {status} {name}")
        if not result:
            all_pass = False

    return all_pass


def main():
    """Run all verification checks."""
    print("=" * 60)
    print("sift v0.5.0 Implementation Verification")
    print("=" * 60)

    results = {
        "config.py": check_config_injection(),
        "main.py": check_main_validate_only(),
        "doctor.py": check_doctor_validation(),
        "e2e_tests": check_e2e_tests(),
        "version": check_version(),
        "changelog": check_changelog(),
    }

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    for name, result in results.items():
        status = "✓" if result else "✗"
        print(f"{status} {name}")

    all_pass = all(results.values())

    if all_pass:
        print("\n✓ All checks passed! Ready for testing and commit.")
        return 0
    else:
        print("\n✗ Some checks failed. Please review above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
