# Changelog

All notable changes to `sift` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [1.0.0] - 2026-03-24

### Added
- **Production release**: sift graduates from Alpha to Production/Stable (`Development Status :: 5`)
- All v0.8.0 features and adversarial security fixes included (see below)

### Changed
- Version classifier updated: `3 - Alpha` → `5 - Production/Stable`

### Fixed (Beta Test — post-adversarial-review)
- **F-01 (security)**: `Alert.redact()` now also clears matching keys in `alert.raw`; previously, redacting `user` left `raw["user"]` intact and IOC extraction would re-surface the email as a cluster IOC
- **F-03 (consistency)**: `--format <unknown>` now exits with code 2 and an explicit error message (was: silent warning + fallback to rich)
- **F-04 (ux)**: invalid `--redact-fields` names now show a user-friendly error message with exit 2 (was: raw Python traceback)
- **F-05 (ux)**: `--enrich-mode` without `--enrich` now prints a warning instead of silently having no effect
- **F-08 (validation)**: `--chunk-size -1` now exits with code 2 (was: silently treated as 0)
- **F-09 (spec)**: STIX Bundle now includes `"spec_version": "2.1"` at the bundle level (STIX 2.1 compliance)
- **F-11 (ux)**: `sift doctor` now shows `(N warning(s) — optional features unavailable)` instead of the misleading "passed or warned"

### Fixed (post-beta backlog — included in v1.0.0)
- **F-02 (chunking)**: `merge_triage_reports()` now runs a second-pass Union-Find merge (`_merge_ioc_overlapping_clusters`) to restore IOC-overlap clustering across chunk boundaries; cross-chunk phishing campaigns cluster correctly
- **F-06 (display)**: Score display unified to 2 decimal places (`:.2f`) in Rich table, detail view, and console output — matches JSON export values exactly
- **F-07 (cache)**: `AlertCache.put()` now serializes datetime objects correctly (`json.dumps(..., default=str)`); cache was silently failing to write on every run; stderr now shows explicit `Cache hit/miss (fingerprint…)` message
- **F-10 (validation)**: Phantom alerts generated from empty records (e.g. `{}`) are filtered after normalization; exits with code 2 and a clear error message instead of triaging an empty cluster
- **F-12 (ux)**: `--filter` now reports match count to stderr: `Filter 'priority >= HIGH': 1/5 cluster(s) matched.`

---

## [0.8.0] - 2026-03-24

### Added (v0.8.0 rest — completed alongside adversarial review)
- **Field-level Alert Redaction**: `Alert.redact(fields)` method — creates a copy with specified fields replaced by `[REDACTED]`; supports `title`, `description`, `source_ip`, `dest_ip`, `user`, `host`, `iocs`, `raw`
- **AlertRedactionConfig**: New `AppConfig.redaction` section with `fields: list[str]` and `redact_raw: bool`
- **`--redact-fields` CLI flag**: Comma-separated field list on `sift triage`; applied before summarization
- **ATT&CK Technique Validation**: `sift/pipeline/attck.py` — `TechniqueValidator` rejects malformed IDs (enforces `^T\d{4}(?:\.\d{3})?$` regex); invalid IDs logged as WARNING and dropped
- **Alert Chunking**: `sift/pipeline/chunker.py` — `chunk_alerts()` + `merge_triage_reports()`; processes large batches sequentially and merges TriageReports; `--chunk-size` CLI flag
- **`ClusteringConfig.chunk_size`**: Config-file support for default chunk size (0 = disabled)
- **`--enrich-mode local`**: `EnrichmentMode.LOCAL` — pure heuristic IOC analysis (Shannon entropy, suspicious TLDs/keywords, private IP, IP-in-URL detection); no external API calls, no consent prompt
- **`sift/enrichers/local_heuristics.py`**: Shannon entropy > 3.8, 17 suspicious TLDs, 14 suspicious keywords
- **Doctor Check #13**: ATT&CK module import check in `sift doctor`

### Security Fixes (Adversarial Code Review)
- **CRITICAL — Injection non-blocking**: `prompt.py` now builds `safe_clusters` with redacted alerts before LLM submission (previously only logged warning, sent raw data)
- **CRITICAL — Newline bypass in Pattern 1**: Injection detector Pattern 1 now uses `re.DOTALL`; adversary could split "ignore\nprevious instructions" across newlines to bypass
- **CRITICAL — Pattern 2 false negative**: "Instead, output …" (comma between "instead" and verb) was not matched; pattern extended to `instead[\s,;.]+(?:of\s+)?verb`
- **HIGH — Argument injection via IOCs**: `barb_bridge.py` and `vex_bridge.py` now pass `--` before IOC argument to prevent IOC strings like `--flag=value` from being interpreted as CLI flags
- **HIGH — Cache path traversal**: `AlertCache._validate_cache_dir()` rejects `cache_dir` paths resolving to `~/.ssh/`, `~/.gnupg/`, `/etc/`, `/usr/`, `/bin/`, `/sbin/`, `/boot/`, `/sys/`, `/proc/`
- **MEDIUM — STIX pattern injection**: `stix.py` `_pattern_from_ioc()` now escapes `]` characters (in addition to `\` and `'`) to prevent STIX pattern breakout
- **LOW — Whitelist dead code**: `PromptInjectionConfig.whitelist_patterns` was never passed to `PromptInjectionDetector`; now wired through `_injection_whitelist` attribute in `_build_summarizer()`

### Testing
- New `tests/test_redaction.py`: 16 tests
- New `tests/test_attck_validation.py`: 19 tests
- New `tests/test_chunking.py`: 15 tests
- New `tests/test_enrich_local.py`: 19 tests
- Total: 670 → **740 tests**, 100% pass rate, 3 pre-existing skips

---

## [0.8.0-beta] - 2026-03-23

### Added
- **Edge Case Tests**: `test_edge_cases.py` — 32 tests for normalizers, IOC extractor, prioritizer, cache, and filter DSL boundary conditions
- **Pipeline Integration Tests**: `test_pipeline_edge_cases.py` — 15 end-to-end tests combining v0.5–v0.7 features (cache+filter, STIX+filter, 500-alert perf, unicode CSV, injection-laden input)
- **Doctor: Cache Check** — `_check_cache_directory()` verifies `~/.sift/cache/` is accessible and writable (12 total checks)
- **Doctor: STIX Export Check** — `_check_stix_export()` verifies STIXExporter imports cleanly
- **README: Advanced Usage** — filter DSL reference, cache usage, STIX pipeline examples, max_clusters YAML config
- **README: Metrics Section** — `sift metrics` command with output description
- **README: Validation & Security** — `--validate-only` and prompt injection detection documented
- **README: Output Formats** — added `stix` row to output formats table
- **README: LLM Providers** — added `mock` provider row

### Fixed
- README Workflow section: removed stale "future --enrich flag" language (enrichment live since v0.4.0)
- Filter DSL: documented that `IN` operator is category-only (numeric fields use `> / >=` comparisons)

### Testing
- New `test_edge_cases.py`: 32 tests
- New `test_pipeline_edge_cases.py`: 15 tests
- Total: 670 tests (623 + 47), 100% pass rate, 3 pre-existing skips
- Noteworthy: 500-alert batch clusters in < 5s (O(n log n) sliding window from v0.7.0 confirmed)

---

## [0.7.0] - 2026-03-23

### Added
- **Result Caching**: `--cache` flag on `sift triage` enables SQLite-backed result caching by input fingerprint (TTL 1h, LRU eviction, opt-in)
- **CacheConfig**: New config model with `enabled`, `ttl_seconds`, `max_entries`, `cache_dir` fields; disabled by default
- **AlertCache**: `sift/cache.py` — SQLite WAL-mode cache with lazy TTL expiry, LRU eviction, hit/miss stats
- **Clustering Optimization**: Sliding-window time bucketing (O(n log n) instead of O(n²)) for category/IP-pair passes
- **Early Termination**: `max_clusters` parameter on `cluster_alerts()` for preview mode and streaming pipelines
- **IOC Index Confirmation**: Verified inverted IOC index in clustering (O(n×ioc_count), not O(n²) pair loop)
- `cache_enabled` field in `AppConfig` for config-file opt-in to caching

### Fixed
- Clustering time-window passes now use sorted sliding deque — no more naive/aware datetime comparison errors in mixed timestamp datasets

### Testing
- New `tests/test_cache.py`: 20 tests for cache operations, eviction, stats, persistence, config
- New `tests/test_clusterer_performance.py`: 15 tests for clustering performance (timing at 1k/5k alerts), IOC index, window bucketing, early termination
- Total test count: 623 tests (588 + 35), 100% pass rate
- All existing tests remain green (no regressions)

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

[Unreleased]: https://github.com/duathron/sift/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/duathron/sift/compare/v0.8.0...v1.0.0
[0.8.0]: https://github.com/duathron/sift/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/duathron/sift/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/duathron/sift/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/duathron/sift/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/duathron/sift/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/duathron/sift/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/duathron/sift/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/duathron/sift/releases/tag/v0.1.0
