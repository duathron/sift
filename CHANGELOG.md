# Changelog

All notable changes to `sift` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.6.0] - 2026-03-23

### Added
- **Metrics Module**: `sift/metrics.py` with `TriageMetrics` and `MetricsCollector` for comprehensive triage analytics
- **Metrics Command**: `sift metrics <file>` displays cluster statistics, alert counts, IOC distribution, and category breakdown
- **STIX 2.1 Export**: `--format stix` flag outputs clusters in STIX 2.1 JSON Bundle format for threat intelligence sharing
- **Advanced Filtering**: `--filter` flag on `sift triage` with boolean DSL for post-triage cluster selection (e.g., `priority >= HIGH`)
- **IOC Classification**: Automatic classification of IOCs into types (IPv4, IPv6, domain, email, URL, MD5, SHA1, SHA256)
- **Metrics Table Formatting**: Rich Table output with top categories and IOC distribution visualization

### Testing
- New `test_metrics.py`: 8 comprehensive tests for metrics collection and IOC classification
- IOC classification tests: IPv4, IPv6, domain, URL, hash, email, mixed types
- Metrics formatting tests: edge cases (0 clusters, large counts)
- All existing 484 tests pass (no regressions)
- Total: 492 tests expected (484 + 8)

### Backward Compatible
- All new parameters optional; existing scripts unchanged
- Filter application non-blocking (warning on parse failure)
- STIX export graceful fallback to existing formats

---

## [0.5.0] - 2026-03-22

### Added
- **Validation Layer**: Strict JSON-Schema validation of `SummaryResult` objects via `SummaryResultSchema`
- **Prompt Injection Detection**: `PromptInjectionDetector` with 5 pattern types (instruction override, output manipulation, JSON escapes, encoded payloads, shell injection)
- **PromptInjectionConfig**: New config section with `enabled` flag and `whitelist_patterns` list for fine-grained control
- **MockSummarizer**: Deterministic, zero-dependency mock provider for reproducible testing and CI/CD pipelines
- **Validation Fallback**: Automatic fallback to `TemplateSummarizer` when LLM validation fails (non-blocking)
- **E2E Test Suite**: 8 comprehensive end-to-end validation tests covering injection detection, validation, mock provider, and schema compliance
- **--validate-only Flag**: New CLI flag on `sift triage` for validation-only mode (parse, validate, skip output rendering)
- **Doctor Check**: "LLM schema validation" diagnostic check in `sift doctor`
- **Few-Shot Prompts**: Provider-specific few-shot examples in prompt.py (Anthropic, OpenAI, Ollama)

### Fixed
- Validation layer prevents malformed LLM output from breaking pipeline
- Injection detection prevents prompt injection attacks before LLM submission
- Config backward-compatible: all new fields are optional with sensible defaults

### Testing
- New `test_e2e_validation.py`: 18 tests for end-to-end validation scenarios
- New `test_injection_detector.py`: 43 tests for injection detection patterns
- New `test_mock_summarizer.py`: 18 tests for mock provider
- New `test_prompt_providers.py`: 10 tests for provider-specific prompts
- New `test_validation.py`: 25 tests for validation layer
- Total test count: 484 tests (351 existing + 133 new), 100% pass rate
- All existing tests remain green (no regressions)
- Ruff linting: 9 E501 errors (acceptable for long docstring examples)
- MyPy strict mode: 0 critical type errors

---

## [0.4.0] - 2026-03-22

### Added
- `--enrich` flag on `sift triage`: enriches extracted IOCs via barb (phishing URLs) and vex (VirusTotal)
- `sift/enrichers/` module: protocol, BarbBridge, VexBridge, EnrichmentRunner
- Subprocess-based bridge (CLI-agnostic, no internal API coupling)
- `--enrich-mode` flag: `all` | `barb` | `vex` (default: all)
- `--yes` / `-y` flag: skip enrichment consent prompt
- Consent prompt for external API calls (GDPR-aware)
- `EnrichmentContext` included in `TriageReport` JSON export
- `EnrichConfig.consent_given` config option to pre-approve enrichment
- Kali Linux installation docs (pipx recommended)
- Python 3.11+ compatibility (was 3.12+)

---

## [0.3.0] - 2026-03-22

### Added
- Complete test suite: 309 tests across 9 modules, 100% pass rate
- `test_normalizers.py`: 56 tests covering Splunk, generic JSON, and CSV normalizer edge cases
- `test_dedup.py`: 19 tests for SHA-256 fingerprinting and time-window deduplication
- `test_ioc_extractor.py`: 50 tests for IPv4/IPv6, domains, URLs, hashes, and email extraction
- `test_clusterer.py`: 19 tests for Union-Find clustering with 4-pass strategy (IOC overlap, category+time, IP-pair, residual)
- `test_prioritizer.py`: 15 tests for score calculation and 5-tier priority assignment
- `test_models.py`: 24 tests for Pydantic model validation
- `test_summarizers.py`: 15 tests for template and LLM-based summarization
- `test_export.py`: 12 tests for JSON and CSV export
- `test_pipeline_integration.py`: 22 tests for end-to-end pipeline with fixture data
- Pytest configuration with testpaths and collection markers

---

## [0.2.0] - 2026-03-22

### Added
- `sift/main.py`: Typer CLI entry point with commands: `triage` | `doctor` | `config` | `version`
- Fixed SIFT ASCII banner in `sift/banner.py` (clearer figlet rendering)
- Updated README.md with corrected ASCII art banner
- `sift/doctor.py`: 9 diagnostic checks (Python version, config, LLM packages, enrichment, env vars, PATH)
- Live smoke tests against 4 fixture files: phishing_campaign, lateral_movement, mixed, fp_cluster
- Exit code behavior verified: 1 for HIGH/CRITICAL clusters, 0 for NOISE/LOW/MEDIUM, 2 for errors
- Python 3.14 virtual environment setup with pip install -e .
- Config loading with priority: CLI flags > env vars > ~/.sift/config.yaml > defaults

---

## [0.1.0] - 2026-03-22

### Added

- Initial release of `sift` — AI-Powered Alert Triage Summarizer for SOC teams
- Generic JSON normalizer supporting alert arrays and NDJSON input
- Splunk export normalizer handling `results` wrapper and Splunk field conventions
- CSV normalizer with automatic header detection and field extraction
- Deduplication pipeline stage to collapse identical or near-identical alerts before analysis
- IOC extraction from alert fields: IPv4/IPv6 addresses, domains, file hashes (MD5/SHA1/SHA256), and URLs
- Multi-pass alert clustering: IOC overlap, category + time-window correlation, and IP-pair grouping
- Score-based cluster prioritization with five tiers: NOISE / LOW / MEDIUM / HIGH / CRITICAL
- Template-based summarizer producing structured triage output with no LLM dependency
- Anthropic Claude summarizer via `anthropic` SDK (optional `[llm]` extra)
- OpenAI summarizer via `openai` SDK (optional `[llm]` extra)
- Ollama summarizer for local inference with configurable endpoint (no extra required)
- Rich terminal output with priority-colored cluster table and IOC highlights
- JSON export with full cluster, signal, and IOC detail for downstream tooling
- CSV export suitable for SIEM import or spreadsheet analysis
- `sift doctor` diagnostics command: validates config, LLM connectivity, and optional dependencies
- PyPI version check on startup with advisory notice when a newer release is available
- `sift config --show` command to display resolved configuration
- Exit codes: `0` (clean), `1` (HIGH/CRITICAL clusters found), `2` (error)
- `--no-dedup` flag to skip deduplication for raw pass-through analysis
- `--quiet` / `-q` flag to suppress banner for scripted and piped use
- Stdin support via `-` filename for pipeline integration

---

[Unreleased]: https://github.com/duathron/sift/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/duathron/sift/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/duathron/sift/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/duathron/sift/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/duathron/sift/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/duathron/sift/releases/tag/v0.1.0
