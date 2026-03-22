# sift

```
 ___  _  __  _
/ __|| ||  \| |_
\__ \| || |) |  _|
|___/|_||__/|_|
```

**AI-Powered Alert Triage Summarizer for SOC Teams**

`sift` ingests raw security alerts, deduplicates and clusters related events, scores them by priority, and delivers a structured triage summary — with optional AI-generated analysis. Part of the barb → vex → sift SOC workflow trilogy.

---

## Features

- Ingest alerts from generic JSON, Splunk exports, or CSV
- Deduplicate noisy alert streams before analysis
- Extract IOCs (IPs, domains, hashes, URLs) from alert fields automatically
- Cluster related alerts by IOC overlap, category + time window, or IP-pair correlation
- Score clusters across five priority tiers: NOISE / LOW / MEDIUM / HIGH / CRITICAL
- AI summarization via Anthropic Claude, OpenAI, or Ollama (local) — or template-based with no LLM required
- Rich terminal output with priority-colored cluster table
- Export to JSON or CSV for downstream tooling
- `sift doctor` diagnostics to verify configuration and LLM connectivity
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

# Future: IOC enrichment via barb/vex
pip install "sift-triage[enrich]"

# Everything
pip install "sift-triage[llm,enrich]"
```

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

**Export triage report to JSON:**
```bash
sift triage alerts.json -f json -o report.json
```

**Run diagnostics:**
```bash
sift doctor
```

---

## Workflow

`sift` is the third stage of a SOC analyst trilogy. Use `barb` to score and flag suspicious URLs in incoming data, pass flagged IOCs to `vex` for VirusTotal enrichment, then feed the enriched alert data into `sift` for cluster-level triage and summarization. Each tool is useful standalone; together they cover URL analysis → IOC reputation → alert prioritization in a single scriptable pipeline. A future `--enrich` flag will automate barb and vex calls directly from within `sift triage`.

---

## Input Formats

| Format | Description | Notes |
|---|---|---|
| Generic JSON | Array of alert objects or NDJSON | Any field schema; sift normalizes automatically |
| Splunk export | JSON export from Splunk Search | Handles `results` wrapper and Splunk field names |
| CSV | Comma-separated alert rows | First row treated as header; all fields extracted |

Pass `-` as the filename to read from stdin:
```bash
splunk-cli export | sift triage -
```

---

## LLM Providers

| Provider | Extra | Environment Variable | Notes |
|---|---|---|---|
| `template` | *(none)* | — | Default; no LLM required |
| `anthropic` | `[llm]` | `ANTHROPIC_API_KEY` | Claude via Anthropic API |
| `openai` | `[llm]` | `OPENAI_API_KEY` | GPT via OpenAI API |
| `ollama` | *(none)* | `SIFT_OLLAMA_URL` (optional) | Local inference; defaults to `http://localhost:11434` |

Set the default provider in `~/.sift/config.yaml` or via the `SIFT_PROVIDER` environment variable.

---

## Output Formats

| Flag | Output |
|---|---|
| `rich` (default) | Color-coded cluster table in the terminal |
| `console` | Plain-text output, safe for logging |
| `json` | Structured JSON with all cluster and IOC data |
| `csv` | Flat CSV suitable for SIEM import or spreadsheets |

Use `-f` / `--format` to select output format, and `-o` / `--output` to write to a file.

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

## License

MIT — see [LICENSE](LICENSE) for details.

Author: Christian Huhn
