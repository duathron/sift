# Prompt Injection Detection for sift v0.5.0

## Overview

This document describes the prompt injection detection feature implemented in sift v0.5.0 to mitigate prompt injection attacks in alert data before submission to LLMs.

## Files

- **sift/summarizers/injection_detector.py** (265 lines)
  - `InjectionFinding` Pydantic model for detection results
  - `SeverityLevel` enum (WARNING, CRITICAL)
  - `PromptInjectionDetector` class with pattern matching and redaction
  - Utility functions: `scan_alert()`, `redact_alerts()`

- **tests/test_injection_detector.py** (43 test functions organized in 9 test classes)
  - Test coverage for all 5 injection patterns
  - Tests for field detection, redaction, logging, edge cases
  - Tests for case-insensitive matching and severity levels

- **sift/summarizers/prompt.py** (Modified)
  - Integration of injection detection in `build_cluster_prompt()`
  - Non-blocking security scanning with logging

## Implemented Patterns

The detector scans for 5 types of injection patterns:

### 1. Instruction Override
**Pattern**: "ignore previous instructions", "disregard prior directives", "forget the preceding prompt"
**Regex**: Matches variants like `(ignore|disregard|forget|dismiss|bypass|override).{0,20}?(previous|prior|earlier|above|preceding).{0,20}?(instruction|directive|prompt|command)`
**Severity**: CRITICAL
**Use Case**: Attacker tries to override system prompts

### 2. Output Manipulation
**Pattern**: "instead output", "output instead", "return instead"
**Regex**: Matches variants like `(instead|rather|output|respond|return|generate|create).{0,20}?(instead|output|respond|return|generate|create|:)`
**Severity**: CRITICAL
**Use Case**: Attacker tries to redirect LLM output

### 3. JSON Escape Sequences
**Pattern**: Escaped quotes, newlines, unicode escapes (`\"`, `\n`, `\u0041`)
**Regex**: `\\(?:["\\/bfnrtu]|u[0-9a-fA-F]{4})`
**Severity**: WARNING
**Use Case**: Attacker tries to break out of JSON context

### 4. Encoded Payloads
**Pattern**: Base64 or hex encoded strings (20+ characters)
**Regex**: Matches `[A-Za-z0-9+/]{20,}={0,2}` or `([0-9a-fA-F]{2}){10,}`
**Severity**: WARNING
**Use Case**: Attacker obfuscates payload

### 5. Shell Command Injection
**Pattern**: Command substitution (`$(...)`, backticks), variable expansion (`$VAR`)
**Regex**: `(?:\$\([^)]*\)|`[^`]*`|\$\w+)`
**Severity**: CRITICAL
**Use Case**: Attacker tries to execute shell commands

## API

### InjectionFinding Model

```python
from sift.summarizers.injection_detector import InjectionFinding, SeverityLevel

finding = InjectionFinding(
    field="title",              # Alert field name
    pattern_type="instruction_override",  # Type of pattern
    severity=SeverityLevel.CRITICAL,     # WARNING or CRITICAL
    redaction="[REDACTED]",     # Suggested redaction
    value_preview="ignore..."   # Truncated preview (optional)
)
```

### PromptInjectionDetector Class

```python
from sift.models import Alert
from sift.summarizers.injection_detector import PromptInjectionDetector

detector = PromptInjectionDetector(case_insensitive=True)

# Detect patterns in an alert
findings: list[InjectionFinding] = detector.detect(alert)

# Redact suspicious fields
redacted_alert: Alert = detector.redact_alert(alert, findings)
```

### Utility Functions

```python
from sift.summarizers.injection_detector import scan_alert, redact_alerts

# Scan single alert
findings = scan_alert(alert)

# Scan and redact list of alerts
redacted = redact_alerts([alert1, alert2, alert3])
```

## Integration with sift

The detector is integrated into the `build_cluster_prompt()` function in `sift/summarizers/prompt.py`:

1. **Timing**: Scans alerts before LLM submission
2. **Behavior**: Non-blocking (logs warnings but doesn't halt processing)
3. **Logging**: Warnings logged when injection patterns are detected
4. **Example**:
   ```
   WARNING:sift.summarizers.prompt:Injection pattern(s) detected in alert abc123:
   instruction_override, shell_injection (severity: CRITICAL, CRITICAL)
   ```

## Test Coverage

43 test functions covering:

- Pattern Detection (all 5 patterns)
  - `TestIgnoreInstructionsPattern` (3 tests)
  - `TestInsteadOutputPattern` (3 tests)
  - `TestJsonEscapePattern` (3 tests)
  - `TestBase64HexPattern` (3 tests)
  - `TestShellCommandPattern` (4 tests)

- General Detection (3 tests)
  - Empty alerts return no findings
  - Clean alerts pass through
  - Legitimate command text not flagged

- Field Detection (4 tests)
  - Detection in title, description, category, raw fields

- Redaction Logic (4 tests)
  - Alert field masking
  - Raw field handling
  - Empty findings handling
  - Batch redaction

- Case Sensitivity (3 tests)
  - Case-insensitive matching verified

- Severity Levels (5 tests)
  - Correct severity for each pattern type

- Logging (2 tests)
  - Warnings logged on findings
  - No warnings on clean alerts

- Model Tests (1 test)
  - InjectionFinding Pydantic model validation

- Edge Cases (2 tests)
  - Multiple patterns in same field
  - Very long alert fields with truncation

## Design Decisions

1. **Non-blocking**: Detection doesn't prevent alert processing (security advisory only)
2. **Case-insensitive**: Matches uppercase, mixed-case variants
3. **Whitelisting**: No allowlist needed; patterns are specific enough to avoid false positives
4. **Redaction**: Optional; findings available for decision-making
5. **Logging**: Non-intrusive logging at WARNING level
6. **Performance**: Lightweight regex-based detection, single pass through alerts

## Future Enhancements (v0.6.0+)

- Optional: Add config flag `injection_detection_enabled` (default: True)
- Optional: Add config for severity thresholds
- Optional: Add pattern whitelisting per organization
- Optional: Machine learning-based injection detection
- Optional: Integration with external security APIs

## References

- OWASP: Prompt Injection (https://owasp.org/www-community/attacks/Prompt_Injection)
- CWE-94: Improper Control of Generation of Code
- MITRE ATT&CK: Prompt Injection (T1589)
