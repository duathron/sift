# sift

```
  ____ ___ _____ _____
 / ___|_ _|  ___|_   _|
 \___ \| || |_    | |
  ___) | ||  _|   | |
 |____/___|_|     |_|
```

**AI-Powered Alert Triage Summarizer for SOC Teams**

`sift` ingests raw security alerts, deduplicates and clusters related events, scores them by priority, and delivers a structured triage summary — with optional AI-generated analysis. Part of the barb → vex → sift SOC workflow trilogy.

---

## Features

- Ingest alerts from generic JSON, Splunk exports (including NDJSON forwarder
  output), CSV, and Sysmon-format CSV (Image / CommandLine / EventID /
  ParentImage aliases).
- Deduplicate noisy alert streams before analysis (fingerprint includes
  host and user so distinct endpoints stay distinct).
- Extract a wide range of IOC types automatically:
  - Network: IPv4, IPv6, domains, URLs, email addresses
  - File hashes: MD5, SHA1, SHA256, SHA512, ssdeep, TLSH, JARM, JA3 / JA3S
    (keyword-anchored), imphash
  - File observables: Windows executables / scripts (`.exe`, `.dll`, `.ps1`,
    `.docm`, …) including underscore-bearing malware names
  - Vulnerability and framework references: CVE IDs, MITRE ATT&CK technique
    IDs (T1xxx / T1xxx.yyy)
  - Persistence indicators: Windows registry keys (`HKLM\…`, `HKCU\…`)
  - Obfuscation indicators: PowerShell encoded blocks (`-enc <b64>`,
    `FromBase64String("…")`) — surfaced as a SHA-256 stub, never as raw
    base-64
  - Tunnel and cloud-abuse domains: ngrok, serveo, trycloudflare,
    Discord webhooks, Telegram bot URLs, paste sites — auto-tagged
    `high` severity
  - Defang refang preprocessor: `hxxp://`, `[.]`, `(.)`, `[at]`/`[dot]`,
    fullwidth Unicode (`．`, `＠`), zero-width / BOM strips
  - Null-hash sentinels (Sysmon empty `IMPHASH`, hashes-of-empty-bytestring)
    are silently dropped
- Severity-hint multipliers: PowerShell-encoded execution → `critical`,
  persistence registry keys / tunnel domains / paste sites → `high`,
  feeding directly into cluster prioritisation, Jira priority bumps,
  TheHive tags, and STIX export.
- Cluster related alerts by IOC overlap, category + time window, or IP-pair
  correlation. Overflow alerts (when `max_clusters` is hit) land in an
  explicit `Other` cluster instead of being silently dropped.
- Score clusters across five priority tiers: NOISE / LOW / MEDIUM / HIGH / CRITICAL
- AI summarization via Anthropic Claude, OpenAI, Ollama (local), or
  template-based with no LLM required. The `--no-llm` flag forces the
  template provider for fully offline / keyless triage.
- Rich terminal output with priority-colored cluster table and a
  per-cluster severity-hint column.
- Export to JSON, CSV, STIX 2.1, HTML, or Markdown for downstream tooling.
  PowerShell-encoded payloads are sanitised in every export path by default;
  pass `--include-raw-payload` for forensic-mode output.
- Filter clusters using a boolean DSL (`--filter 'priority >= HIGH AND ...'`)
- Enrich IOCs via barb (phishing URL analysis) and vex (VirusTotal reputation)
  with `--enrich`. Bridges run concurrently (`ThreadPoolExecutor`); IOCs are
  case-normalised and refanged before the cache dedup pass to collapse
  duplicate API calls.
- Cache triage results by input fingerprint with `--cache` (opt-in, 1h TTL,
  thread-safe SQLite).
- Validate LLM output schema, normalize text via NFKC, and detect prompt
  injection attacks. PowerShell-encoded payloads are sanitised before any
  LLM submission.
- Ticketing for TheHive 5 and Jira Service Management with severity-hint
  aware priority promotion (e.g. a cluster containing PowerShell-encoded
  IOCs goes straight to `Highest` in Jira).
- **Typed IOC model** — every extracted IOC carries its detected type
  (`ioc`, `domain`, `url`, `sha256`, …) in a new `iocs_typed` field alongside
  the existing `iocs: list[str]` (additive; wire format unchanged). STIX
  export uses the detected type directly; the Rich terminal view shows a
  per-cluster type-count header (e.g. `ip ×3  domain ×9  sha256 ×5`).
- **Shift-handover reports** — `-f html` and `-f md` produce self-contained,
  human-readable shift-handover documents (cluster cards, priority, IOC tables,
  AI narrative). Both formats respect field-level redaction at the model layer.
- `sift metrics <file>` command for cluster and IOC distribution statistics
- `sift doctor` diagnostics to verify configuration, LLM connectivity, and dependencies
- `sift --version` eager flag (works without a subcommand) alongside the existing `version` subcommand
- PyPI version check on startup

---

## Installation

```bash
pip install sift-triage
```

**Optional extras:**

```bash
# LLM summarization (Anthropic + OpenAI)
pip install "sift-triage[llm]"

# IOC enrichment via barb/vex
pip install "sift-triage[enrich]"

# Everything
pip install "sift-triage[llm,enrich]"
```

### Kali Linux / Debian

```bash
# Recommended: use pipx for isolated CLI tool installation
sudo apt install pipx   # or: pip install pipx
pipx install sift-triage

# With LLM support
pipx install "sift-triage[llm]"

# With barb + vex enrichment
pipx install "sift-triage[enrich]"
```

> **Note:** Python 3.11+ required. Kali Linux 2024+ includes Python 3.12 by default.
> On older systems: `sudo apt install python3.12 python3.12-venv`

---

## Quick Start

**Triage a JSON alert file:**
```bash
sift triage alerts.json
```

**Triage with AI summarization (Anthropic Claude):**
```bash
sift triage alerts.json --summarize --provider anthropic
```

**Pipe from Splunk or another tool:**
```bash
cat splunk_export.json | sift triage -
```

**Triage offline / without an LLM (template-only summary):**
```bash
sift triage alerts.json --no-llm
```

**Forensic-mode export (keep raw PowerShell base-64 payloads):**
```bash
sift triage alerts.json -f json --include-raw-payload -o forensic.json
```

**Export triage report to JSON:**
```bash
sift triage alerts.json -f json -o report.json
```

**Export triage report as STIX 2.1 bundle:**
```bash
sift triage alerts.json -f stix -o bundle.json
```

**Filter to HIGH and CRITICAL clusters only:**
```bash
sift triage alerts.json --filter 'priority >= HIGH'
```

**Enable result caching (skip reprocessing on repeated runs):**
```bash
sift triage alerts.json --cache
```

**Show metrics for an alert file:**
```bash
sift metrics alerts.json
```

**Run diagnostics:**
```bash
sift doctor
```

**Enrich IOCs via barb (phishing URLs) + vex (VirusTotal):**
```bash
sift triage alerts.json --enrich --summarize
```

**Enrich only via barb (no VirusTotal API key needed):**
```bash
sift triage alerts.json --enrich barb
```

**Correlate alerts across multiple sources:**
```bash
# Two files — merged before clustering
sift triage firewall.json edr_alerts.json

# Mix of files and a directory (scanned recursively)
sift triage baseline.json new_alerts/ --filter 'priority >= HIGH'

# All .json/.csv files in a folder
sift triage /var/log/siem/ --summarize --provider anthropic
```

**Generate a shift-handover report:**
```bash
# HTML (self-contained, embedded CSS)
sift triage alerts.json -f html -o handover.html

# Markdown (paste into Jira/Confluence or commit to a repository)
sift triage alerts.json -f md -o handover.md
```

**Redact sensitive fields before any output or LLM submission:**
```bash
sift triage alerts.json --redact-fields source_ip,user,host
```

---

## Configuration

sift stores settings in `~/.sift/config.yaml` and credentials in `~/.sift/.env` (mode 600). Both files are created automatically on first use.

**Priority chain:** CLI flags > `SIFT_LLM_KEY` env var > `~/.sift/.env` > `~/.sift/config.yaml` > defaults

### Show current config

```bash
sift config --show
```

### Set LLM API key

The API key is stored in `~/.sift/.env` and is never written to `config.yaml`.

```bash
sift config --api-key sk-ant-...          # Anthropic Claude
sift config --api-key sk-...              # OpenAI
sift config --unset-api-key               # Remove key
```

Alternatively, set the `SIFT_LLM_KEY` environment variable directly.

### Set default provider and model

```bash
sift config --provider anthropic
sift config --provider openai --model gpt-4o
sift config --provider ollama --model llama3
sift config --provider template           # no LLM required (default)
```

### Set output defaults

```bash
sift config --quiet                       # suppress banner by default
sift config --no-quiet                    # re-enable banner
sift config --default-format json         # default output format
sift config --default-format rich         # back to Rich table (default)
```

### Set pipeline defaults

```bash
sift config --chunk-size 100             # process large batches in chunks of 100
sift config --chunk-size 0               # disable chunking (default)
sift config --cache                      # enable result caching by default
sift config --no-cache                   # disable caching (default)
sift config --enrich-consent             # pre-approve IOC enrichment (no prompt)
sift config --no-enrich-consent          # require prompt before enrichment (default)
```

Run `sift config --help` for the full option reference.

---

## Workflow

`sift` is the third stage of a SOC analyst trilogy. Use `barb` to score and flag suspicious URLs in incoming data, pass flagged IOCs to `vex` for VirusTotal enrichment, then feed the enriched alert data into `sift` for cluster-level triage and summarization. Each tool is useful standalone; together they cover URL analysis → IOC reputation → alert prioritization in a single scriptable pipeline. The `--enrich` flag automates barb and vex calls directly from within `sift triage`.

---

## Input Formats

| Format | Description | Notes |
|---|---|---|
| Generic JSON | Array of alert objects or NDJSON | Any field schema; sift normalizes automatically |
| Splunk export | JSON export from Splunk Search | Handles `results` wrapper and Splunk field names |
| CSV | Comma-separated alert rows | First row treated as header; all fields extracted |

**Multiple sources:** Pass any number of files and/or directories. sift merges all alerts before dedup and clustering, enabling cross-source correlation:

```bash
sift triage firewall.json edr.json ids.csv
sift triage /var/log/siem/           # all .json/.csv/.ndjson/.log files, recursively
sift triage baseline.json new_alerts/
```

**stdin:** Pass `-` as the filename to read from stdin:
```bash
splunk-cli export | sift triage -
```

---

## Large Data & Memory Management

sift uses a **per-file streaming pipeline** that bounds peak RAM regardless of total input size:

| Input Size | Behavior |
|---|---|
| < 50 MB | File read entirely into memory — fastest |
| 50 MB – 500 MB | Streaming read (5k-line batches), single clustering pass |
| > 500 MB | **Sub-file chunking**: batches of 100k alerts each run through the full pipeline independently, then merge via IOC-overlap Union-Find |
| Multiple files | Each file processed and freed independently; cross-source correlation restored at merge |

### Recommended flags for large datasets

```bash
# 1–10 GB: use --drop-raw to halve per-alert RAM (drops 80-column raw dict)
sift triage big_flows.csv --drop-raw

# 10+ GB: combine --drop-raw with explicit chunk size
sift triage *.csv --drop-raw --chunk-size 100000

# Tuning via config (persistent)
sift config --chunk-size 50000          # smaller chunks = less RAM per batch
```

### Scale guidelines

| Scale | Recommendation |
|---|---|
| < 100 MB (< 200k rows) | Works as-is, no tuning needed |
| 100 MB – 1 GB | `--chunk-size 100000` recommended |
| 1 GB – 10 GB | `--drop-raw --chunk-size 100000` — expect 10–60 min |
| > 10 GB | Pre-filter to specific time windows or attack types first |
| > 50 GB | Use a SIEM (Splunk, Elastic) to aggregate, then export alerts for sift |

### Config options

```yaml
# ~/.sift/config.yaml
clustering:
  chunk_size: 100000               # alerts per batch (0 = auto)
  sub_chunk_threshold_mb: 500      # files above this get sub-file chunking
  sub_chunk_size: 100000           # alerts per sub-file batch
  drop_raw_threshold_mb: 500       # total input above this triggers --drop-raw automatically
  chunk_threshold_mb: 200          # total input above this enables auto-chunking
  default_chunk_size: 100000       # chunk size used when auto-chunking kicks in
```

The three auto-tuning thresholds (`drop_raw_threshold_mb`, `chunk_threshold_mb`, `default_chunk_size`) were previously hard-coded in the pipeline's tuning module. They now live in `ClusteringConfig` so you can override them in `config.yaml` without touching CLI flags. Defaults are byte-identical to the previous behavior.

---

## AI Summarization

The `--summarize` flag adds an AI-generated executive summary and per-cluster recommendations on top of the standard triage output. Without `--summarize`, sift runs entirely offline with no LLM required.

```bash
sift triage alerts.json --summarize --provider anthropic
```

The summary includes:
- **Executive summary** — one paragraph situational assessment across all clusters
- **Per-cluster narrative** — what happened, which systems/users are involved, likely attack stage
- **Recommendations** — prioritized action items (IMMEDIATE / WITHIN_1H / WITHIN_24H / MONITOR)

---

### Provider Setup

#### Anthropic (Claude) — recommended

```bash
pip install "sift-triage[llm]"
sift config --provider anthropic --api-key sk-ant-...
sift triage alerts.json --summarize
```

Default model: `claude-sonnet-4-6`. Override with `--model`:

```bash
sift triage alerts.json --summarize --provider anthropic --model claude-opus-4-6
```

API key resolution order: `sift config --api-key` (`~/.sift/.env`) → `ANTHROPIC_API_KEY` env var.

---

#### OpenAI (GPT)

```bash
pip install "sift-triage[llm]"
sift config --provider openai --api-key sk-...
sift triage alerts.json --summarize
```

Default model: `gpt-4o-mini`. Override with `--model gpt-4o`.

API key resolution order: `sift config --api-key` (`~/.sift/.env`) → `OPENAI_API_KEY` env var.

---

#### Ollama (local, no API key)

Run any local model without sending data to an external API — recommended for sensitive environments.

```bash
# Install and start Ollama: https://ollama.com
ollama pull llama3.2

sift config --provider ollama
sift triage alerts.json --summarize
```

Default model: `llama3.2`. Default endpoint: `http://localhost:11434`. Override with:

```bash
SIFT_OLLAMA_URL=http://my-server:11434 sift triage alerts.json --summarize --provider ollama --model mistral
```

---

#### Template (default, no LLM)

Generates a structured summary using predefined rules — no API key, no network calls.

```bash
sift triage alerts.json --summarize --provider template
```

Use this for air-gapped environments or to test the summarization pipeline without an LLM.

---

### Provider comparison

| Provider | Install extra | API key required | Data leaves machine | Default model |
|----------|--------------|-----------------|---------------------|---------------|
| `template` | — | No | No | — |
| `mock` | — | No | No | — (testing only) |
| `anthropic` | `[llm]` | Yes | Yes (Anthropic API) | `claude-sonnet-4-6` |
| `openai` | `[llm]` | Yes | Yes (OpenAI API) | `gpt-4o-mini` |
| `ollama` | — | No | No (local) | `llama3.2` |

---

## Enrichment (barb + vex)

The `--enrich` flag enriches extracted IOCs using the sister tools:

| Tool | PyPI | What it does | Required |
|------|------|-------------|----------|
| barb | `barb-phish` | Heuristic phishing URL analysis | No (local) |
| vex  | `vex-ioc`    | VirusTotal IOC reputation lookup | API key via `VT_API_KEY` |

```bash
# Install enrichment extras
pip install "sift-triage[enrich]"

# Run with enrichment (barb + vex)
sift triage alerts.json --enrich all

# Barb only (no API key needed)
sift triage alerts.json --enrich barb

# vex only
sift triage alerts.json --enrich vex

# Skip consent prompt
sift triage alerts.json --enrich all --yes
```

sift limits enrichment to 20 IOCs per run to avoid API rate limits.

---

## Ticketing

Create incident tickets directly from triage output — no copy-paste required.

| Provider | Auth | Ticket type |
|----------|------|-------------|
| **TheHive 5** | Bearer token | Alert (analyst can promote to Case) |
| **Jira Service Management** | Email + API token | Issue (configurable type) |
| **dry-run** | none | JSON preview to stdout or file |

### Setup

```bash
# Install HTTP dependency
pip install "sift-triage[ticket]"

# TheHive
sift config --ticket-provider thehive --ticket-url https://thehive.example.com
sift config --ticket-token <THEHIVE_API_TOKEN>

# Jira
sift config --ticket-provider jira \
            --ticket-url https://company.atlassian.net \
            --ticket-project SOC \
            --ticket-jira-email analyst@company.com
sift config --ticket-token <JIRA_API_TOKEN>
```

API tokens are stored in `~/.sift/.env` (mode 600) — never in `config.yaml`.

### Usage

```bash
# Create ticket for top-priority cluster (uses configured default provider)
sift triage alerts.json --ticket thehive

# Jira ticket
sift triage alerts.json --ticket jira

# Preview ticket JSON without sending
sift triage alerts.json --ticket dry-run
sift triage alerts.json --ticket-output ticket.json

# One ticket per HIGH/CRITICAL cluster
sift triage alerts.json --ticket thehive --ticket-all

# Check connectivity
sift doctor
```

### Ticket content

Each ticket contains:
- **Title**: `[sift] {SEVERITY} | {cluster label}`
- **Summary**: LLM narrative (if `--summarize`) or auto-generated description
- **Timeline**: alerts sorted chronologically (up to 10 entries)
- **IOCs**: all unique indicators from the cluster
- **ATT&CK**: technique IDs mapped from alerts
- **Recommendations**: actionable checklist from AI summary
- **Confidence**: clustering confidence score (0–100 %)

> **TheHive**: IOCs are automatically mapped as Observables (IP / hash / URL / domain).
> **Jira**: description uses Atlassian Document Format with checkbox task lists for recommendations.

---

## Output Formats

| Flag | Output |
|---|---|
| `rich` (default) | Color-coded cluster table in the terminal |
| `console` | Plain-text output, safe for logging |
| `json` | Structured JSON with all cluster and IOC data |
| `csv` | Flat CSV suitable for SIEM import or spreadsheets |
| `stix` | STIX 2.1 bundle JSON for threat intelligence platforms |
| `html` | Self-contained HTML shift-handover report (embedded CSS, cluster cards, IOC table) |
| `md` | Markdown shift-handover report suitable for Jira/Confluence, ticket attachments, or a shift-handover repository |

Use `-f` / `--format` to select output format, and `-o` / `--output` to write to a file.

```bash
# Save an HTML handover report
sift triage alerts.json -f html -o handover.html

# Save a Markdown handover report
sift triage alerts.json -f md -o handover.md
```

---

## Typed IOCs

Every extracted IOC has a detected type. The `-o json` output carries `iocs_typed` (new) alongside the existing `iocs` list — both are always present and the existing `iocs: list[str]` shape is unchanged:

```json
{
  "clusters": [
    {
      "iocs": ["10.0.0.1", "evil.example.com", "d41d8cd98f00b204..."],
      "iocs_typed": [
        {"value": "10.0.0.1",             "type": "ip"},
        {"value": "evil.example.com",      "type": "domain"},
        {"value": "d41d8cd98f00b204...",   "type": "md5"}
      ]
    }
  ]
}
```

The typed field is present on both cluster and alert objects. STIX export uses the detected type to select the correct STIX observable. The Rich terminal view shows a type-count header per cluster — for example `domain ×9  ip ×3  sha256 ×5` — giving analysts a quick sense of what indicators are present before reading the full table.

When redaction is active, `iocs_typed` is blanked in lockstep with `iocs` — no IOC value leaks through the typed field.

---

## Field Redaction

`--redact-fields` closes three leak channels when any field is active:

1. **Raw dict suppression** — `alert.raw` is blanked from all output formats (JSON, HTML, Markdown, STIX). Without this, raw verbatim data would appear in the output even when named fields were redacted.
2. **Extraction gate** — because `alert.raw` is blank, the IOC extractor's raw-dict pass has nothing to mine. IOC extraction from non-redacted named fields continues unchanged.
3. **IOC-value drop** — any extracted IOC whose value exactly matches a redacted field's pre-redaction value is dropped from both `iocs` and `iocs_typed`. IOC counts decrease when redaction is active — this is expected behavior.

```bash
# Redact specific fields
sift triage alerts.json --redact-fields source_ip,user,host

# Persist redaction defaults in config
sift config --redact-fields source_ip,user,host
```

**Forensic override.** Setting `redaction.redact_raw: true` in `~/.sift/config.yaml` keeps `alert.raw` in the output even when `--redact-fields` is active — for forensic captures where the raw dict is needed despite redaction.

```yaml
# ~/.sift/config.yaml
redaction:
  redact_raw: true   # Keep raw in output for forensic captures (default: false = suppress raw)
```

> **Security invariant:** sift never sends alert data to a cloud LLM without a redaction-config check.

### Known residuals (Phase 1)

Phase 1 closes the three channels above. Two residual forms remain and are not yet closed — both share the same root cause:

**a) Plain-text residual.** If the redacted value also appears in the *text* of a non-redacted field (for example `description="scan from 10.0.0.1"`), that text is not scrubbed. The value will still appear in that field's output.

**b) Substring IOC residual.** If a *larger* IOC is extracted from a non-redacted field and the redacted value is a substring of it (for example `description="see http://10.0.0.1/x"` → the url IOC `http://10.0.0.1/x`), the IOC is not dropped — channel 3 uses exact-value matching, not substring matching, so the URL is not caught even though the IP appears inside it.

**Operator fix for both:** add the carrying field to `--redact-fields` (for example `--redact-fields source_ip,description`). That blanks the field text, prevents the larger IOC from being extracted, and removes the plain-text occurrence.

Phase 2 (value-scrub) is required to close both residuals without requiring the operator to enumerate every carrying field.

---

## Advanced Usage

### Alert Filtering

Use `--filter` to apply a boolean DSL to the cluster list after triage. Only matching clusters are included in the output.

```bash
# Only HIGH and CRITICAL clusters
sift triage alerts.json --filter 'priority >= HIGH'

# Malware or phishing clusters with more than 3 IOCs
sift triage alerts.json --filter 'category IN (malware, phishing) AND ioc_count > 3'

# Exclude low-signal categories
sift triage alerts.json --filter 'NOT category IN (false_positive)'

# Combine priority and alert count conditions
sift triage alerts.json --filter 'priority >= MEDIUM AND alert_count >= 5'
```

Supported fields: `priority`, `category`, `ioc_count`, `alert_count`.
Supported operators: `>=`, `<=`, `>`, `<`, `=`, `IN (...)`, `NOT`, `AND`, `OR`.

### Result Caching

Use `--cache` to cache triage results by SHA-256 fingerprint of the input. Repeated runs over the same input return instantly from the cache (1-hour TTL, stored in `~/.sift/cache/`).

```bash
# First run: processes and caches the result
sift triage alerts.json --cache

# Subsequent runs with the same file: returns from cache
sift triage alerts.json --cache

# Combine with other flags; cache stores the full triage output
sift triage alerts.json --cache --summarize --provider anthropic
```

### STIX 2.1 Export Pipeline

Export triage results as a STIX 2.1 threat intelligence bundle for ingestion into SIEM or TIP platforms.

```bash
# Export to STIX bundle file
sift triage alerts.json -f stix -o bundle.json

# Combined enrichment and STIX export
sift triage alerts.json --enrich -f stix -o enriched_bundle.json

# Pipe STIX output to another tool
sift triage alerts.json -f stix | jq '.objects | length'
```

### Max Clusters

Limit the number of clusters returned by the pipeline using `max_clusters` in `~/.sift/config.yaml`. When the cluster count exceeds the limit, only the highest-priority clusters are retained. This is useful for large alert volumes where downstream tooling has per-report limits.

```yaml
clustering:
  max_clusters: 50
```

---

## Metrics

The `sift metrics` command runs the full normalization, dedup, and clustering pipeline over an alert file and displays summary statistics without generating a triage report.

```bash
sift metrics alerts.json
```

Output includes:
- Total cluster count and alert count
- Average cluster size
- Top alert categories by frequency
- IOC type distribution (IPs, domains, hashes, URLs)
- AI summary success rate (if summaries were previously generated)

```bash
# Skip deduplication for raw counts
sift metrics alerts.json --no-dedup

# Use a custom config file
sift metrics alerts.json --config /path/to/config.yaml
```

---

## Validation and Security

sift validates all LLM outputs against a strict JSON schema. Use `sift validate` to parse and report format and count without running the full pipeline:

```bash
# Validate alert file structure without running triage
sift validate alerts.json
```

A built-in prompt injection detector scans alert fields for five pattern categories: instruction overrides, output manipulation, JSON escapes, encoded payloads, and shell injection. Suspicious content is flagged and summarization falls back to the template provider automatically. The injection engine is shared with barb and vex via `shipwright_kit.security.injection` so a fix propagates to all three tools at once.

> **Security invariant:** sift never sends alert data to a cloud LLM without a redaction-config check. Core clustering is rule-based and deterministic; AI summarization is opt-in.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Triage complete — no HIGH or CRITICAL clusters found |
| `1` | Triage complete — one or more HIGH or CRITICAL clusters found |
| `2` | Error — invalid input, configuration failure, or LLM error |

Exit code `1` is designed for use in CI pipelines and automated response playbooks.

---

## Configuration

```bash
sift config --show    # display current configuration
sift doctor           # verify config, LLM connectivity, and dependencies
```

Configuration is resolved in priority order: CLI flags > environment variables > `~/.sift/config.yaml` > defaults.

---

## Part of the SOC Trilogy

| Tool | Role | PyPI |
|---|---|---|
| [barb](https://github.com/duathron/barb) | Heuristic phishing URL analyzer | `barb-phish` |
| [vex](https://github.com/duathron/vex) | VirusTotal IOC enrichment | `vex-ioc` |
| **sift** | Alert triage summarizer | `sift-triage` |

---

## Author

**Christian Huhn** — building security tooling for SOC/DFIR workflows.

- GitHub: [@duathron](https://github.com/duathron)
- LinkedIn: [Christian Huhn](https://www.linkedin.com/in/christian-huhn-76a407114)

## License

MIT — see [LICENSE](LICENSE) for details.

Author: Christian Huhn
