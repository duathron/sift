# sift — Project History and Documentation

**Author:** Christian Huhn (GitHub: [duathron](https://github.com/duathron))
**Version:** 1.2.1 (released) / 1.3.0 pending (on-main, unreleased)
**Date:** 2026-06-12
**Repository:** https://github.com/duathron/sift

---

## The Idea

### The Problem

SOC teams drown in alerts. A single SIEM, EDR, and firewall stack produces thousands of events per day, most of them noise — duplicate hits, the same scanner tripping the same rule across a hundred hosts, low-signal informational entries burying the handful of events that actually matter. An analyst opening a raw export sees a flat list with no structure: no sense of which alerts belong to the same incident, which indicators repeat, or which cluster deserves attention first.

The obvious reach for "an AI tool" carries its own problems. Pasting raw alert data — which often contains usernames, hostnames, internal IPs, and attacker-controlled strings — into a cloud LLM is a data-governance and prompt-injection liability that most SOCs cannot accept. And a tool that *only* works with an LLM is useless in an air-gapped environment or when no API key is configured.

### The Solution

sift is a Python CLI that ingests raw security alerts, deduplicates and clusters related events, scores them by priority, and delivers a structured triage summary. Its design rests on a few deliberate choices:

- **The core is rule-based, not AI.** Normalization, deduplication, IOC extraction, clustering, and prioritization are all deterministic. sift produces a complete, useful triage report with no LLM and no network access.
- **AI summarization is strictly opt-in** via the `--summarize` flag. Without it, sift runs entirely offline. The base install works exactly the same whether or not an LLM is configured.
- **sift works standalone.** It needs neither barb nor vex installed. An optional `--enrich` flag integrates them (barb for phishing-URL analysis, vex for VirusTotal reputation) when present, but standalone operation is always first-class.
- **Alert data is never sent to a cloud LLM without a redaction-config check.** Field-level redaction and a prompt-injection scanner sit in front of every LLM submission; a local-only provider (Ollama) and a deterministic template provider are available for sensitive environments. When `--redact-fields` is active, `alert.raw` is suppressed from every output format and the IOC extractor's raw-dict pass is gated — see the Redaction section.

sift is the third stage of a SOC analyst trilogy — barb (URL analysis) → vex (IOC reputation) → sift (alert triage). Each tool stands alone; together they cover URL analysis → IOC reputation → alert prioritization in one scriptable pipeline.

---

## Technical Architecture

### The Pipeline

A triage run is a deterministic pipeline; the two AI-touching stages are opt-in:

```
Ingest → Normalize → Deduplicate → Extract IOCs → Cluster → Prioritize → Enrich (opt) → Summarize (opt) → Output
```

- **Ingest** — read one or more files, directories, or stdin (`-`). Directories are scanned recursively for `.json` / `.csv` / `.ndjson` / `.jsonl` / `.log` files; all sources merge into a single alert pool before dedup so correlation works across sources.
- **Normalize** — `NormalizerProtocol` implementations map heterogeneous inputs (generic JSON / NDJSON, Splunk exports, CSV including Sysmon-format CSV) onto a common `Alert` model.
- **Deduplicate** — collapse near-identical alerts by a SHA-256 fingerprint (the tuple includes `host` and `user` so distinct endpoints and accounts stay distinct).
- **Extract IOCs** — a wide-coverage extractor pulls network indicators, hashes, file observables, CVE / MITRE IDs, registry keys, and PowerShell-encoded blocks out of alert fields, with a defang/refang preprocessor up front.
- **Cluster** — multi-pass Union-Find grouping by IOC overlap, category + time window, and IP-pair correlation. When `max_clusters` is hit, overflow alerts land in an explicit `Other` cluster instead of being silently dropped.
- **Prioritize** — score each cluster across five tiers (NOISE / LOW / MEDIUM / HIGH / CRITICAL), with severity-hint multipliers (`critical` ×1.4, `high` ×1.2) for high-risk IOC types.
- **Enrich (opt)** — `--enrich` routes IOCs through barb and vex via subprocess bridges; requires explicit consent for the external API calls.
- **Summarize (opt)** — `--summarize` adds an LLM (or template) executive summary and per-cluster recommendations.
- **Output** — Rich table, plain console, JSON, CSV, or STIX 2.1.

### Stack and Dependencies

Dependencies were kept deliberately minimal — the base install is five packages plus the shared library:

| Package | Purpose |
|---|---|
| `typer` | CLI framework with argument parsing and subcommands |
| `rich` | Terminal formatting (tables, panels, colours) |
| `pydantic` (v2) | Configuration and data models with validation |
| `pyyaml` | Configuration file (`config.yaml`) reading and writing |
| `python-dotenv` | `~/.sift/.env` credentials loading |
| `shipwright-kit` | Shared Shipwright library — prompt-injection engine, eval harness, and config mechanism, consumed from PyPI (`>=0.6.0,<0.7.0`). Added in v1.2.0; backs the injection detector, the config loader, and the CI eval gates (see Core Design Decisions and v1.2.0). |

Optional extras keep heavier integrations out of the base install:

- `pip install "sift-triage[llm]"` — `anthropic` + `openai`
- `pip install "sift-triage[enrich]"` — `barb-phish` (vex is invoked as the `vex` CLI when present)
- `pip install "sift-triage[ticket]"` — `httpx` for TheHive / Jira ticketing
- `pip install "sift-triage[all]"` — everything

STIX 2.1 generation uses only the standard library — no `stix2` dependency.

### Package Structure

```
sift/
├── main.py                    # Typer CLI: triage / metrics / validate / doctor / config / version
├── banner.py                  # SIFT ASCII banner (TTY-aware suppression)
├── config.py                  # Pydantic AppConfig; load/save; delegates skeleton to shipwright_kit.config
├── cache.py                   # SQLite result cache (TTL, thread-safe RLock)
├── models.py                  # Pydantic v2 models (IOC, Alert, Cluster, TriageReport, …)
├── filtering.py               # boolean filter DSL for post-triage cluster selection
├── metrics.py                 # sift metrics — cluster / IOC distribution statistics
├── tuning.py                  # auto-tuning of chunk size / drop-raw by input size
├── doctor.py                  # diagnostic checks (config, LLM, enrichment, ticketing)
├── version_check.py           # PyPI version-check advisory
├── normalizers/               # NormalizerProtocol: generic JSON, Splunk, CSV (+ Sysmon aliases)
├── pipeline/                  # dedup, ioc_extractor, clusterer, prioritizer, chunker, attck
│   └── redaction.py           # Phase 1 value-level redaction: raw-suppress, extraction-gate, IOC-drop
├── summarizers/               # SummarizerProtocol: template, anthropic, openai, ollama, mock
│                              #   + prompt builder, JSON-schema validation, injection_detector
├── enrichers/                 # barb_bridge, vex_bridge, runner, local_heuristics (EnricherProtocol)
├── ticketing/                 # TheHive 5, Jira, dry-run providers + mapper (TicketingProtocol)
└── output/                    # formatter (Rich + console), export (JSON/CSV/HTML/MD), STIX 2.1
    ├── html.py                # HTML shift-handover report (self-contained, embedded CSS)
    └── md.py                  # Markdown shift-handover report

eval/                          # detection-quality gates (run in CI), uses shipwright_kit.eval
├── run_injection_eval.py      # prompt-injection precision/recall
├── run_ioc_eval.py            # IOC-classifier binary precision/recall
├── run_ioc_type_eval.py       # per-type IOC classification accuracy
└── corpus/                    # labeled CSV corpora
```

### Core Design Decisions

#### Standalone CLI, Unix Pipes First

The founding architecture decision (MeetUp, 2026-03-22, unanimous) was a standalone CLI with Unix pipes as the primary interface — Option A. The rationale: forensic integrity per tool, the smallest attack surface per process, and the Unix philosophy of composable single-purpose tools. sift reads from stdin (`-`), writes machine-readable output, and signals state through exit codes, so it slots into shell scripts and SOAR playbooks. barb/vex integration is an explicit opt-in (`--enrich`), never an implicit dependency — sift must run with neither installed.

#### Rule-Based Core, Opt-In AI

Everything that produces the triage report — normalize, dedup, IOC extraction, clustering, prioritization — is deterministic and runs offline. AI is layered on top via `--summarize` and never default-on (MeetUp constraint). This keeps sift usable with no API key, makes its output reproducible for tests, and means an LLM outage or a missing key degrades to a complete template-based report rather than a failure. The `--no-llm` flag forces the template provider regardless of config, for fully offline or keyless triage and CI.

#### Four-Provider AI with Template Fallback

The `SummarizerProtocol` is backed by four providers — Anthropic Claude, OpenAI, Ollama (local), and a deterministic Template summarizer — plus a Mock provider for tests. Anthropic defaults to `claude-sonnet-4-6`, OpenAI to `gpt-4o-mini`, Ollama to `llama3.2` at `http://localhost:11434`. Ollama and Template keep data on the machine; the two cloud providers are the only paths where data leaves, and only when explicitly selected. Provider selection, model override (`--model`), and the local-only options are all configurable.

#### Redaction Before Any Cloud LLM

Before alert data reaches an LLM prompt, two guards run: field-level redaction (`--redact-fields`, or persisted config defaults) replaces named fields with `[REDACTED]`, and a prompt-injection scanner inspects every alert field. The constraint is hard: *sift never sends alert data to a cloud LLM without a redaction-config check.* PowerShell-encoded base-64 payloads are sanitised to a SHA-256 stub before they can reach any prompt, and on a detected injection pattern the affected field is redacted and summarization can fall back to the template provider. The injection engine itself is single-sourced from `shipwright_kit.security.injection` (see below).

On main (pending 1.3.0), `--redact-fields` also closes three output-path leak channels via `pipeline/redaction.py`: `alert.raw` is blanked before extraction (Channel 1), the IOC extractor's raw-dict pass is automatically gated by the blank raw (Channel 2), and extracted IOCs matching a pre-redaction field value are dropped (Channel 3). Two residuals remain in Phase 1 — see the "On-Main" section and "Known residuals" for the exact scope and operator fix. `redaction.redact_raw: true` in `config.yaml` is the forensic override that keeps raw in the output even when redaction is active.

#### Configuration with Priority Hierarchy

Configuration (`sift/config.py`) follows a clear priority chain:

```
CLI flags  >  SIFT_LLM_KEY env var  >  ~/.sift/.env  >  ~/.sift/config.yaml  >  defaults
```

`AppConfig` is a Pydantic `BaseModel` with nested submodels (`ClusteringConfig`, `ScoringConfig`, `SummarizeConfig`, `OutputConfig`, `EnrichConfig`, `PromptInjectionConfig`, `AlertRedactionConfig`, `TicketingConfig`, …). Secrets are never written to `config.yaml`: the LLM key lives in `~/.sift/.env` (mode 600), as do ticket-provider tokens (`SIFT_THEHIVE_TOKEN` / `SIFT_JIRA_TOKEN`). The `~/.sift/` directory is created at mode 700.

Since v1.2.0, `load_config()` delegates the resolve→load→validate skeleton to `shipwright_kit.config` (the shared, secure config mechanism — `app_dir("sift")` for the path and the candidate-resolution plumbing). sift keeps its own `AppConfig` schema, the `~/.sift/.env` dotenv load, the `SIFT_LLM_KEY` override, and the `save_config` / `.env` credential helpers verbatim. The priority chain above is preserved.

#### Shared Prompt-Injection Engine

The injection detector (`sift/summarizers/injection_detector.py`) supplies sift's `Alert`-shaped field extraction and redaction, but the pattern-matching engine — all patterns, NFKC normalisation, the IOC-field exemption, and whitelist handling — comes from the shared `shipwright_kit.security.injection` engine. sift's detector walks every scannable alert field (title, description, category, source, user, host, every string in `raw`, and every entry in `iocs`) and delegates each to the shared `detect()`. Because the engine is single-sourced across vex, barb, and sift, a bypass fixed once propagates to all three tools — instead of being patched three times in three repos.

#### Exit Codes for Automation

```
0  → triage complete, no HIGH or CRITICAL clusters
1  → triage complete, one or more HIGH or CRITICAL clusters found
2  → error (invalid input, configuration failure, or LLM error)
```

Exit `1` is designed for CI pipelines and automated response playbooks. Ticketing is post-processing — a ticket-send failure never changes the triage exit code.

#### SQLite Result Cache

`sift/cache.py` caches a full triage result keyed by a SHA-256 fingerprint of the input (1-hour TTL, LRU eviction, stored in `~/.sift/cache/`). The connection is opened `check_same_thread=False` and every public method is guarded by a re-entrant `threading.RLock`, because the enrichment runner shares the cache across a `ThreadPoolExecutor`.

---

## Feature Development

### triage — the primary command

`sift triage <input…>` runs the full pipeline. It accepts any number of files and/or directories (merged before dedup for cross-source correlation), reads stdin via `-`, and selects output with `-f/--format` and `-o/--output`. A per-file streaming pipeline bounds peak RAM to the largest single file; files above 500 MB are sub-chunked into 100k-alert batches that each run the pipeline independently and merge via IOC-overlap Union-Find — sift can therefore process multi-GB datasets without loading them whole.

### IOC extraction (industry-standard coverage)

The extractor recognises a wide indicator vocabulary: IPv4/IPv6, domains, URLs, emails; MD5/SHA1/SHA256/SHA512, ssdeep, TLSH, JARM, and keyword-anchored JA3/JA3S/imphash; Windows executable/script filenames (including underscore-bearing malware names); CVE IDs and MITRE ATT&CK technique IDs (T1xxx / T1xxx.yyy); Windows registry keys; and PowerShell-encoded blocks. A defang/refang preprocessor normalises `hxxp(s)://`, `[.]`/`(.)`/`{.}`, `[://]`, `[dot]`/`(dot)`, `[at]`/`(at)` (domain-context guarded), fullwidth Unicode lookalikes, and zero-width/BOM characters before extraction. Null-hash sentinels (Sysmon empty `IMPHASH`, hashes of the empty bytestring) are dropped. High-risk types carry a severity hint — PowerShell-encoded execution → `critical`; persistence registry keys, tunnel/cloud-abuse domains (ngrok, trycloudflare, …), and paste sites → `high` — which feeds cluster prioritization, Jira priority bumps, TheHive tags, and STIX export.

### Output formats and filtering

Seven output formats: `rich` (default), `console`, `json`, `csv`, STIX 2.1, `html`, and `md`. PowerShell-encoded payloads are sanitised in every export path by default; `--include-raw-payload` is the forensic escape hatch. The two handover formats (`html` and `md`) are available on main, pending v1.3.0; they accept `-f html` / `-f md` on the `triage` command. A boolean filter DSL (`--filter 'priority >= HIGH AND category IN (malware, phishing)'`) selects clusters post-triage over the fields `priority`, `category`, `ioc_count`, `alert_count`.

### Enrichment (barb + vex)

`--enrich` routes extracted IOCs through barb (phishing-URL heuristics) and vex (VirusTotal reputation) via subprocess bridges — CLI-agnostic, with no internal API coupling. The bridges run concurrently (`ThreadPoolExecutor`); IOCs are case-normalised and refanged before a cache-dedup pass so duplicate API calls collapse. Enrichment is capped at 20 IOCs per run, is gated behind a consent prompt for the external calls (`--yes` to skip), and supports a pure-heuristic local mode that makes no network calls.

### Ticketing

`--ticket thehive|jira|dry-run` creates an incident ticket from the top-priority cluster (`--ticket-all` for one per HIGH/CRITICAL cluster). The provider-agnostic `TicketDraft` carries title, summary, severity/priority, confidence, timeline, IOCs, ATT&CK technique IDs, and recommendations; providers map it to TheHive 5 Alerts (with IOC→Observable typing) or Jira issues (Atlassian Document Format with checkbox task lists). A dry-run provider serialises the draft to JSON for preview.

### Diagnostics and metrics

`sift doctor` checks configuration, LLM connectivity, enrichment availability, and ticketing connectivity. `sift metrics <file>` runs normalize/dedup/cluster and reports cluster counts, average cluster size, top categories, and IOC-type distribution without producing a full triage report. `sift validate <file>` parses and validates alert files without running triage.

---

## Version History

sift reached a Production/Stable 1.0.0 on 2026-03-24 and accumulated a substantial 1.1.x line before the 1.2.0 release documented here. The full record lives in `CHANGELOG.md`; this section summarises the 1.1.x train and details v1.2.0.

### The 1.0.x foundation (summary)

1.0.0 graduated from Alpha to Production/Stable, carrying the v0.x core — multi-format normalizers, dedup, IOC extraction, multi-pass clustering, five-tier prioritization, the four-provider summarizer with template fallback, JSON/CSV/STIX export, the boolean filter DSL, result caching, prompt-injection detection, and field-level redaction — plus a round of adversarial-review security fixes. The 1.0.x patches (`1.0.1` → `1.0.161`) added the full `sift config` CLI and `~/.sift/.env` credentials, multi-file/directory input with cross-source correlation, the per-file streaming pipeline and sub-file chunking for multi-GB data, an auto-tuning engine, `sift validate`, and prompt/normalizer refinements.

### The 1.1.x line — ticketing, IOC expansion, injection-scanner hardening

The 1.1.x series is the body of work between 1.0 and the 1.2.0 release, grouped by theme:

- **v1.1.0 — Ticketing (FREEZE candidate).** Added the `sift/ticketing/` package: TheHive 5 and Jira Service Management providers, a DryRun provider, the provider-agnostic `TicketDraft` model, `TicketingConfig`, and `--ticket` / `--ticket-output` / `--ticket-all` flags. `httpx` became the optional `[ticket]` extra. ServiceNow was deferred. (918 tests.)

- **v1.1.01 → v1.1.07 — the injection / enrichment patch train.** A run of focused patches: injection-detector base-64 false positives that were silently redacting benign SOC alert titles like "Exfiltration" / "Configuration" (threshold and lookahead fixes, plus a `TestBase64FalsePositives` regression guard); LLM truncation (default `max_tokens` raised 1000 → 4096) and a `--max-tokens` expert flag; a cache-hit crash where a cached `dict` was passed where a `TriageReport` was expected (fixed with `model_validate`, plus a round-trip regression test); CLI argument bugs in the vex/barb bridges (`--` placement and a nonexistent `-q` flag); filename-as-domain and vex list-response crashes in the bridges; and comprehensive enrichment-bridge hardening (markdown-link guard, email guard, private/reserved-IP and non-routable-TLD filtering). v1.1.03 also fixed an API-key leak in `config --show`, config-mutation isolation via `model_copy()`, and Rich markup-injection escaping on exception strings.

- **v1.1.08 — Filename IOC extraction.** A `filename` IOC type and null-sentinel hash filtering.

- **v1.1.10 — IOC extractor expansion + app-wide audit.** The largest 1.1.x release: the defang refang preprocessor, CVE / MITRE / registry-key / PowerShell-encoded / SHA512 / ssdeep / TLSH / JARM extraction, `classify_severity_hint`, and a fixture-corpus regression suite — bundled with 11 P0 ship-blockers and 19 P1 follow-ups from a five-agent app-wide audit. The P0 work plumbed the new IOC types through every consumer (prioritizer multipliers, STIX export, TheHive observable typing, Jira priority, the injection scanner, the prompt sanitiser), and "Option B" sanitisation made PowerShell-encoded payloads SHA-256-stubbed in every output path by default, with `--include-raw-payload` as the forensic opt-out. (1130 tests.)

- **v1.1.101 — Injection-scanner quiet mode (hotfix).** Default scanner output collapsed from one `WARNING` per alert to a single batched summary line (`Injection scanner: N pattern(s) across M alert(s) — redacted`) to stop log flooding on large alert sets, with `--injection-detail` to restore per-alert lines and `--findings-file / -F` to write full findings JSON for forensic review. (1145 tests.)

- **Refang patch (2026-06-01).** Parity with barb v1.5.1: the `[://]` bracketed scheme separator (inserted first in the defang pattern list so it fires before the `hxxp(s?)://` substitution) and the `(dot)` word-form separator. (1160 tests.) This work shipped as part of v1.2.0.

---

## v1.2.0 — Shipwright Onboarding

**Decision:** SIFT, 2026-06-05 — onboard onto the shared `shipwright-kit` library (eval + injection + config) and publish `sift-triage` 1.2.0 to PyPI consuming it from PyPI.

v1.2.0 is the headline release. vex, barb, and sift had independently grown overlapping code — each carried its own prompt-injection pattern set, its own config-loading skeleton, and (for the tools that had one) its own eval runtime. v1.2.0 onboards sift onto **shipwright-kit**, a shared Shipwright library (prompt-injection engine, eval harness, config mechanism) now published to PyPI. The payoff is the classic shared-library benefit: **build or fix something once, and it propagates to every tool that consumes it** — instead of fixing the same injection bypass three times in three repos.

> This 1.2.0 is the Shipwright / detection-quality release. The *originally-planned* v1.2.0 P2 scope — the `Alert.iocs` redesign (`list[str]` → `list[IOC]`) and its architecture MeetUp — is **not** in this release and remains a future item (see Current Status).

### New injection detections: jailbreak and system-prompt exfiltration

Routing the detector through the shared `shipwright_kit.security.injection` engine gave sift two pattern classes it never had:

- **jailbreak / role-override** — "act as an unrestricted assistant", "you are now DAN", and similar.
- **system-prompt exfiltration** — "print the contents of your system prompt", and similar.

These are now flagged in alert fields before they reach LLM summarization. The design is **precision-first**: no benign SOC alert is redacted — the injection eval gate (below) enforces a precision floor of 1.0. sift's detector keeps its `Alert`-shaped field extraction and its `redact_alert` redaction; only the engine is delegated.

### Detection-quality eval gates in CI

v1.2.0 adds three detection-quality gates that run in CI on every push, built on `shipwright_kit.eval` (sift is its second consumer after barb):

- **Prompt-injection precision/recall** (`eval/run_injection_eval.py`) — a binary injection/clean eval over a labeled corpus, delegating the confusion tally, metrics, and gate to the shared harness. Floors: precision 1.0 (the v1.0.16 lesson: no false positives on benign SOC alerts), recall 0.95 with measured 1.0.
- **IOC-classifier binary** (`eval/run_ioc_eval.py`) — is-an-IOC / is-benign precision and recall, both at 1.0.
- **Per-type IOC classification accuracy** (`eval/run_ioc_type_eval.py`) — each IOC must classify to its *exact* type, not merely "is an IOC". A regression that turns a `sha256` into a `sha1`, or a `jarm` into `unknown`, fails the gate even though the binary gate would pass. Because it is multiclass it does not use the shared binary confusion harness; it loads the labeled corpus via `shipwright_kit.eval.corpus` and computes accuracy plus a per-type breakdown directly. Floor 1.0, measured 1.0 across a 20-row corpus covering all 16 types.

Eval `--json` output carries a `schema_version` (`EVAL_SCHEMA_VERSION`, the N6 schema-contract) so downstream consumers can pin the output shape.

### Config delegates to the shared skeleton

`load_config()` now delegates the resolve→load→validate skeleton to `shipwright_kit.config`, eliminating duplicated plumbing. sift keeps its own `AppConfig` schema, the `~/.sift/.env` dotenv load, the `SIFT_LLM_KEY` override, and the `save_config` / `save_credentials` / `.env` helpers verbatim. Characterization tests assert the config behaviour is unchanged before and after the delegation.

### Dependency from PyPI — and a packaging bug fixed at publish

`shipwright-kit` is now resolved from **PyPI** (`>=0.6.0,<0.7.0`) rather than a git URL, so `pip install sift-triage` resolves cleanly (PyPI rejects `git+` dependencies on published packages; publishing the previously git-only library to PyPI is what unblocked using it as a runtime dependency).

A real packaging bug was caught and fixed before publish: `shipwright-kit` had been declared in `[dependency-groups] dev` — a dev-only group — even though `sift.summarizers.injection_detector` and `sift.config` import it **at runtime**. A clean `pip install sift-triage` would therefore have raised `ImportError` on first run, because the dev group is not installed for end users. It was moved to `[project.dependencies]`, and a clean-room install was verified. The lesson is recorded in the project's decision log: a runtime-imported dependency belongs in `[project.dependencies]`, never in a dev group.

### Also in v1.2.0 (earlier in the cycle)

- **`--ticket` on a cache hit** — `sift triage <cached-input> --ticket X` now creates the ticket on a cache hit; previously the cache hit short-circuited and rendered before ticketing could run.
- **Parse-boundary hardening** — property/fuzz tests at the IOC-extraction parse boundary.
- **Refang `[://]` and `(dot)`** — the bracketed scheme separator and the word-form dot separator described in the 1.1.x summary above.

---

## On-Main (unreleased — pending v1.3.0)

The following items are merged to main and included in the open release-please 1.3.0 PR. They are not yet on PyPI. The installed v1.2.1 build does not include them.

### S1 — Typed IOCs (additive, MeetUp 2026-06-11, 4-1 vote)

`IOC(value: str, type: str)` is a new Pydantic model. `Alert` and `Cluster` gain an `iocs_typed: list[IOC]` field alongside the existing `iocs: list[str]` — the existing list is **unchanged** (additive, preserves wire compatibility with the vex `sift_bridge` and all existing `jq` pipelines).

**How it works.** IOCs were already being classified at extraction via `detect_ioc_type()` — the type was then discarded. `iocs_typed` stops discarding it: the type is kept on each IOC object and aggregated per cluster (deduped by value). Two real consumers were wired in the same PR so the field is not dead:

- **STIX export** — `_create_indicator` reads `ioc.type` instead of re-classifying at emit, so STIX observables use the correct type label without a second pass.
- **Rich terminal** — the formatter renders a per-cluster type-count header (for example `domain ×9  ip ×3  sha256 ×5`) giving analysts an at-a-glance IOC composition before reading the full table.

**JSON output shape:**

```json
{
  "clusters": [
    {
      "iocs": ["10.0.0.1", "evil.example.com"],
      "iocs_typed": [
        {"value": "10.0.0.1",        "type": "ip"},
        {"value": "evil.example.com", "type": "domain"}
      ]
    }
  ]
}
```

**Redaction.** Both `Alert.redact()` and the injection `redact_alert()` path blank `iocs_typed` in lockstep with `iocs`. The `ps_encoded` payload scrub in `_sanitize_report` was extended to cover `iocs_typed[].value` so that no raw base-64 payload leaks through the new field.

**Deferred (named, not dropped).** `source_field` provenance, per-IOC `confidence`, and the sift-2.0 collapse of `iocs` → `list[IOC]` (gated on a co-released vex `sift_bridge` patch that handles dict entries) are named follow-ups.

### S2 — `--version` eager flag + tuning thresholds in `ClusteringConfig`

`sift --version` now works as a top-level eager flag — it prints the version and exits without requiring a subcommand. The existing `sift version` subcommand is unchanged.

Three auto-tuning thresholds that were previously hard-coded in `sift/tuning.py` are lifted into `ClusteringConfig` and are now overridable in `~/.sift/config.yaml`:

| Key | Default | Meaning |
|---|---|---|
| `drop_raw_threshold_mb` | 500 | Total input above this triggers automatic `--drop-raw` |
| `chunk_threshold_mb` | 200 | Total input above this enables auto-chunking |
| `default_chunk_size` | 100000 | Chunk size used when auto-chunking kicks in |

Defaults are byte-identical to the previous hard-coded values — existing behavior is unchanged. Operators running on memory-constrained hardware can now lower these thresholds without touching CLI flags.

### S3 — Shift-handover reports (`-f html` and `-f md`)

Two new output formats produce human-readable shift-handover documents suitable for passing between analyst shifts, attaching to a ticket, or committing to a handover repository.

| Format | Use case |
|---|---|
| `html` | Self-contained file with embedded CSS, cluster cards, priority badges, IOC tables, and AI narrative. Dark-themed, no external assets. |
| `md` | Markdown document for Jira/Confluence, ticket attachments, or a shift-handover repository. Uses GitHub-flavored Markdown tables. |

Both formats respect redaction at the model layer — fields already redacted on `Alert` and `Cluster` objects are rendered as-is. The modules never re-surface raw data.

```bash
sift triage alerts.json -f html -o handover.html
sift triage alerts.json -f md   -o handover.md
```

### Value-level redaction fix (Phase 1, MeetUp 2026-06-12)

Prior to this fix, `--redact-fields source_ip` replaced the named field with `[REDACTED]` but left the original value exposed through two additional channels:

1. **`alert.raw` serialized verbatim** into every output format (`export_json → model_dump` always included the raw dict).
2. **IOC re-extraction** — `_collect_text_fields` unconditionally mined raw strings, so a redacted value re-entered `alert.iocs` and `alert.iocs_typed` after redaction ran.

Phase 1 closes three channels:

| Channel | Fix |
|---|---|
| **Raw → output** | `alert.raw` is blanked (`{}`) before extraction when any redact field is active. The blank dict is not serialized into JSON/HTML/MD/STIX. |
| **Raw → re-extracted IOC** | Because Channel 1 blanks raw first, `_collect_text_fields` has nothing to mine from raw — the extraction gate is automatic. |
| **Named-field residual (IOC drop)** | After extraction, any IOC whose value exactly matches a pre-redaction field value is dropped from `iocs` and `iocs_typed`. IOC counts decrease when redaction is active — this is expected. |

**Forensic override.** Set `redaction.redact_raw: true` in `~/.sift/config.yaml` to keep `alert.raw` in the output even when `--redact-fields` is active. This flag is wired on main (it was a dead configuration knob prior to this fix).

**Known residuals (Phase 1 — documented, not closed):**

Two forms of residual remain, both from the same root cause: a redacted value that also appears in a *non-redacted* named field.

*(a) Plain-text residual.* If the value appears in the text of a non-redacted field — for example `description="scan from 10.0.0.1"` — that text is not scrubbed. The value will still appear in that field's output.

*(b) Substring IOC residual.* If a larger IOC is extracted from a non-redacted field and the redacted value is a substring of it — for example `description="see http://10.0.0.1/x"` → a url IOC `http://10.0.0.1/x` — Channel 3's exact-value matching will not drop the URL. The IP appears inside it but the URL as a whole does not equal the redacted value.

The operator fix for both: add the carrying field to `--redact-fields`. Phase 2 (value-scrub, deferred) closes these residuals without requiring the operator to enumerate every carrying field.

---

## Design Decisions (from MeetUps)

sift's feature decisions are made in recorded MeetUps (simple-majority vote, Architect as tie-breaker). The decisions that shaped the current architecture:

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-03-22 | **Standalone CLI (Option A)**, Unix pipes as the primary interface. | Unix philosophy; per-tool forensic integrity; smallest attack surface per process (unanimous). |
| 2026-03-22 | **Optional `--enrich`** integrates barb/vex when installed; standalone operation always works without enrichment. | One command for end-to-end SOC UX, without making the sister tools a hard dependency. |
| 2026-03-22 | **barb and vex are optional extras** (`pip install "sift-triage[enrich]"`); **no implicit key sharing**. | Explicit opt-in prevents accidental API-key exposure across tools. |
| 2026-03-22 | **JSON-Schema validation via Pydantic**, with a published schema. | Input validation prevents silent failures; a schema enables third-party ingestion plugins. |
| 2026-03-22 | **Protocol-based ingestion plugins** (Splunk, QRadar, Elastic), mirroring vex's `EnricherProtocol`. | Extensibility without coupling; supports diverse SIEM environments. |
| 2026-04-13 | **Alert-type-distribution prompt representation** (distinct types + counts + max-severity, severity-sorted) instead of a first-5-alert slice. | The old `[:5]` truncation hid CRITICAL events — in a brute-force scenario the LLM saw only port scans and missed credential dumping. |
| 2026-06-05 | **Onboard onto `shipwright-kit`** (eval + injection + config) and publish 1.2.0 consuming it from PyPI. | DRY across vex/barb/sift — a fix in the shared engine propagates to all. The git-only library was un-publishable as a tool runtime dependency, so it was published to PyPI; lesson: a runtime-imported dep must be in `[project.dependencies]`. |
| 2026-06-11 | **Typed IOCs additive (S1, 4-1 vote).** `iocs_typed: list[IOC]` added; `iocs: list[str]` unchanged. | Breaking `list[dict]` would cause silent zero-IOC enrichment via vex `sift_bridge` with no error — unacceptable at 2am. DFIR's dissent (cleaner model) noted; sift-2.0 collapse is a named follow-up gated on a vex bridge patch. |
| 2026-06-12 | **Value-level redaction Phase 1 (raw-suppression + extraction-gate + IOC-drop).** | Field-level redaction alone was a no-op on the output path — `export_json` serialized `alert.raw` verbatim. Three channels closed; two known residuals documented; Phase 2 (value-scrub) deferred. |

Two standing constraints sit above the feature votes: AI summarization is opt-in and the core stays rule-based; and alert data is never sent to a cloud LLM without a redaction-config check.

### Deferred work

- **The sift-2.0 `Alert.iocs` collapse** — `iocs` → `list[IOC]` (dropping the legacy string list) is a breaking change gated on a co-released vex `sift_bridge` patch and a soak period with the additive `iocs_typed` field (DFIR's end-state, reached safely). The intermediate additive step (S1, typed IOCs) is already on main.
- **`source_field` IOC provenance** — distinguishing an IP in `source_ip` from the same IP in `description.raw` is DFIR's top follow-up ask; deferred pending a field-tagged extraction refactor and a Code-Security policy for `raw.*` key names.
- **Phase 2 value-scrub redaction** — closing the two known residuals (plain-text and substring-IOC forms) without requiring the operator to enumerate every carrying field. A `--redact-values` flag and a `shipwright_kit.security.redaction.scrub_values` primitive are the named design (Expansionist dissent from the 2026-06-12 MeetUp).
- **ServiceNow ticketing** — deferred from v1.1.0 (high integration complexity).
- Further backlog items (e.g. `attck.py`/extractor MITRE-range alignment, process-safe cache eviction, an `IOCSeverityWeights` config sub-model, HTML-entity defang, full ATT&CK TA/S/G ID coverage, recursive `ps_encoded` decode) remain in the P2/P3 backlog.

---

## Current Status and Outlook

### Status v1.2.1 / v1.3.0 pending

**v1.2.1** is the current PyPI release (`pip install sift-triage`). It is covered by 1224 automated tests plus 3 CI eval gates (all green; tests deterministic, no network). The state of the released tool:

- The deterministic core — normalize / dedup / IOC-extract / cluster / prioritize — runs fully offline with no LLM and no API key.
- Industry-standard IOC coverage across 16 types, with a defang/refang preprocessor at full parity with barb and vex.
- Opt-in AI summarization across four providers (Anthropic / OpenAI / Ollama / Template) with a Mock provider for tests, fronted by field redaction and a shared prompt-injection engine.
- Opt-in enrichment via barb and vex (subprocess bridges, concurrent, consent-gated, 20-IOC cap), and a pure-heuristic local mode.
- Ticketing to TheHive 5 and Jira with severity-hint-aware priority promotion; JSON / CSV / STIX 2.1 export with default payload sanitisation.
- v1.2.0 onboarded sift onto **shipwright-kit** (consumed from PyPI): the injection detector delegates to the shared engine and gained jailbreak + system-prompt-exfiltration detection; config delegates to `shipwright_kit.config`; and three detection-quality eval gates (injection, IOC-binary, per-type IOC accuracy) run in CI via `shipwright_kit.eval`. v1.2.1 added the `__version__` literal fix and attribution metadata.

**On main (unreleased, pending release-please v1.3.0):** typed IOCs (S1, additive `iocs_typed`), `sift --version` eager flag and tuning thresholds in `ClusteringConfig` (S2), HTML and Markdown shift-handover reports (S3), and value-level redaction Phase 1 (raw suppression + extraction gate + IOC-value drop). 1280 tests, 3 eval gates 1.0, Skeptic clean-APPROVE. See the "On-Main" section above for the full feature descriptions.

### Outlook

The next release (v1.3.0) folds in the on-main features described above. After that: the `Alert.iocs` sift-2.0 collapse to `list[IOC]` is gated on a co-released vex `sift_bridge` patch and a soak period with the additive `iocs_typed` field. ServiceNow ticketing and the remaining P2/P3 backlog (MITRE-range alignment, cache hardening, extended defang/ATT&CK coverage, recursive `ps_encoded` decode, Phase 2 value-scrub redaction) follow as demand warrants. The shared-library onboarding keeps the cross-tool security and eval surface single-sourced — detection improvements land once and reach all three tools.

---

## Publication

sift is published to PyPI as **`sift-triage`** (`pip install sift-triage`). The package name, the CLI command (`sift`), and the Python module (`sift`) are three independent identifiers.

Publishing uses an **OIDC Trusted Publisher** — there is no long-lived API token stored as a GitHub Secret. The publish workflow (`.github/workflows/publish.yml`) triggers on a published GitHub **Release** (`on: release: [published]`), builds the wheel and sdist, and uploads via `pypa/gh-action-pypi-publish` with `id-token: write`. The job runs in a `pypi` GitHub **Environment**, which requires a human reviewer to approve each upload — so every release to PyPI is explicitly gated by a person. v1.2.0 was published through this reviewer-gated flow with a clean-room `pip install` verified.

---

*Documentation created on 2026-06-05 for v1.2.0 "Shipwright onboarding", based on the complete source tree (`sift/`, `eval/`), `CHANGELOG.md`, `README.md`, `pyproject.toml`, the publish workflow, and the sift project vault (STATUS / DECISIONS / CLAUDE).*
