# Quick Reference: Prompt Injection Detection

## Basic Usage

```python
from sift.summarizers.injection_detector import (
    PromptInjectionDetector,
    scan_alert,
    redact_alerts,
)
from sift.models import Alert

# Option 1: Single alert scanning
alert = Alert(
    id="alert-1",
    title="ignore previous instructions",
    severity=AlertSeverity.HIGH,
)
findings = scan_alert(alert)
for f in findings:
    print(f"{f.field}: {f.pattern_type} [{f.severity}]")

# Option 2: Create detector instance
detector = PromptInjectionDetector()
findings = detector.detect(alert)
if findings:
    redacted = detector.redact_alert(alert, findings)
    print(redacted.title)  # "[REDACTED]"

# Option 3: Batch processing
alerts = [alert1, alert2, alert3]
redacted_alerts = redact_alerts(alerts)
```

## Pattern Reference

| Pattern | Type | Severity | Examples |
|---------|------|----------|----------|
| Instruction Override | `instruction_override` | CRITICAL | "ignore previous instructions", "disregard prior directives" |
| Output Manipulation | `output_manipulation` | CRITICAL | "instead output", "respond instead of" |
| JSON Escapes | `json_escape_sequence` | WARNING | `\"`, `\n`, `\u0041` |
| Encoded Payloads | `encoded_payload` | WARNING | Base64 (20+ chars), hex (10+ pairs) |
| Shell Commands | `shell_injection` | CRITICAL | `$(cmd)`, `` `cmd` ``, `$VAR` |

## Integration Point

```python
# In sift/summarizers/prompt.py
def build_cluster_prompt(report: TriageReport, config: SummarizeConfig) -> str:
    # Scan alerts for injection patterns (non-blocking)
    detector = PromptInjectionDetector()
    for cluster in report.clusters:
        for alert in cluster.alerts:
            findings = detector.detect(alert)
            if findings:
                logger.warning(f"Injection pattern(s) detected in alert {alert.id}...")
    # ... continue with prompt building
```

## Test Examples

```bash
# Run all injection detector tests
pytest tests/test_injection_detector.py -v

# Run specific test class
pytest tests/test_injection_detector.py::TestIgnoreInstructionsPattern -v

# Run with coverage
pytest tests/test_injection_detector.py --cov=sift.summarizers.injection_detector

# Run specific test
pytest tests/test_injection_detector.py::TestIgnoreInstructionsPattern::test_detects_ignore_instructions_exact -v
```

## File Locations

```
sift/
├── summarizers/
│   ├── injection_detector.py (NEW - 278 lines)
│   └── prompt.py (MODIFIED - added detector integration)
└── ../tests/
    └── test_injection_detector.py (NEW - 437 lines, 43 tests)
```

## Data Models

### InjectionFinding
```python
from sift.summarizers.injection_detector import InjectionFinding, SeverityLevel

finding = InjectionFinding(
    field="title",                      # str
    pattern_type="instruction_override",# str
    severity=SeverityLevel.CRITICAL,    # SeverityLevel enum
    redaction="[REDACTED]",             # str
    value_preview="ignore previous...", # Optional[str]
)
```

### SeverityLevel
```python
from enum import Enum

class SeverityLevel(str, Enum):
    WARNING = "WARNING"      # Low-risk pattern
    CRITICAL = "CRITICAL"    # High-risk pattern
```

## Configuration

Currently available options:
```python
detector = PromptInjectionDetector(
    case_insensitive=True  # Default: True (case-insensitive matching)
)
```

Future (v0.6.0):
```python
config.summarize.injection_detection_enabled = True  # Default: True
```

## Logging Output

```
WARNING:sift.summarizers.prompt:Injection pattern(s) detected in alert abc123:
instruction_override, shell_injection (severity: CRITICAL, CRITICAL)
```

## Performance

- **Time**: <1ms per alert (typical 10-20 fields)
- **Memory**: Minimal (regex objects cached)
- **Pattern Compilation**: Once per detector instance

## Error Handling

The detector gracefully handles:
- None field values
- Non-string field types
- Missing optional fields
- Very long field values (truncated for preview)
- Special characters and Unicode
- Empty alerts

## Whitelisting

No explicit whitelisting needed. Patterns are specific enough to avoid false positives:
- "man -k" doesn't trigger shell injection (lacks $() or backticks)
- Normal JSON doesn't trigger escapes (only escaped sequences match)
- Random base64 doesn't trigger (must be 20+ chars)

## Redaction Details

When redaction is applied:
```python
# Before
alert.title = "ignore previous instructions"
alert.description = "normal content"

# After redact_alert()
alert.title = "[REDACTED]"
alert.description = "normal content"  # unchanged

# Raw fields
alert.raw["payload"] = "[REDACTED]"  # nested fields handled
```

## Next Steps

1. **Testing**: Run `pytest tests/test_injection_detector.py -v`
2. **Commit**: `git commit -m "feat: add prompt injection detection"`
3. **Monitor**: Check logs for injection pattern detections
4. **Enhance**: Add config flag in v0.6.0 if needed

## References

- **Module**: `sift.summarizers.injection_detector`
- **Tests**: `tests/test_injection_detector.py`
- **Docs**: `INJECTION_DETECTOR.md`, `IMPLEMENTATION_REPORT.md`
- **OWASP**: https://owasp.org/www-community/attacks/Prompt_Injection
