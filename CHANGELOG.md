# Changelog

All notable changes to `sift` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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

[Unreleased]: https://github.com/duathron/sift/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/duathron/sift/compare/v0.3.0...v0.4.0
[0.1.0]: https://github.com/duathron/sift/releases/tag/v0.1.0
