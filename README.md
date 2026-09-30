# AI-driven Wazuh SOC investigator

A lightweight Python investigation assistant for Wazuh. It retrieves a selected
Wazuh alert through controlled read-only tools, normalizes observed entities,
collects bounded related telemetry, and optionally asks a configured LLM to
produce an evidence-cited assessment.

> **Development status:** This is a lab-stage V1, not an autonomous response
> product. Model output requires analyst review, and the separate 30-case
> analyst evaluation gate has not yet been completed.

## Current workflow

```text
Wazuh alert
  -> normalization and scope filter
  -> entity-derived, one-level correlation
  -> compact evidence packet
  -> optional single LLM assessment
  -> deterministic contract validation
  -> analyst-readable Markdown and JSON report
```

- The model cannot access Wazuh or OpenSearch directly.
- Tool arguments are derived from observed alert entities and validated by Python.
- Correlation is bounded by host, entity, time window, and result limits.
- Unsupported or malformed model output is rejected, downgraded, or flagged.
- Response functions are simulations and never perform automatic containment.
- Prompt and response audits are stored locally under `data/` and excluded from Git.

## Requirements

- Python 3.10 or newer
- Wazuh Indexer/OpenSearch credentials with read-only access
- Optional: Ollama or an Anthropic API key for model assessment
- Direct indexer access or a local SSH tunnel to it

The application uses Python's standard library and has no mandatory third-party
runtime dependency.

## Setup

```powershell
git clone <YOUR_PRIVATE_REPOSITORY_URL>
Set-Location ai-soc-investigator
python -m venv .venv
.\.venv\Scripts\Activate.ps1
Copy-Item .env.example .env
```

Keep Wazuh settings in `.wazuh.local.env`:

```env
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_USERNAME=readonly-user
WAZUH_INDEXER_PASSWORD=replace-me
WAZUH_ALERT_INDEX=wazuh-alerts-*
WAZUH_TELEMETRY_INDEX=wazuh-archives-*
WAZUH_VERIFY_TLS=true
```

Configure only the model provider you intend to use in `.env`. Start with
evidence-only mode to verify Wazuh connectivity without making a model call.

+## Configure the LLM

Model configuration belongs in the local `.env` file, which is excluded from
Git. Never place a real API key in `.env.example`.

### Local Ollama

Ollama does not require an API key:

```env
LLM_PROVIDER=ollama
LLM_MODEL=llama3.2
OLLAMA_BASE_URL=http://localhost:11434
LLM_TIMEOUT_SECONDS=180
OLLAMA_NUM_CTX=4096
OLLAMA_MAX_TOKENS=1000
```

Install or select another local model by changing `LLM_MODEL`.

### Claude API

Create an API key in the Anthropic Console and put it only in `.env`:

```env
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-6
ANTHROPIC_API_KEY=replace-with-your-private-key

LLM_MAX_OUTPUT_TOKENS=1000
LLM_TIMEOUT_SECONDS=180

LLM_INPUT_USD_PER_MTOK=replace-with-current-rate
LLM_OUTPUT_USD_PER_MTOK=replace-with-current-rate
LLM_MAX_REQUEST_USD=0.10
LLM_PROJECT_BUDGET_USD=4.00
LLM_USAGE_LEDGER=data/usage/llm_usage.jsonl
```

The application refuses an Anthropic request when pricing is missing, the
estimated request exceeds `LLM_MAX_REQUEST_USD`, or accumulated estimated
spend would exceed `LLM_PROJECT_BUDGET_USD`. Confirm current rates with
Anthropic before enabling paid calls.

`LLM_MAX_OUTPUT_TOKENS` limits generated output; it is not an API credential.
The API credential is `ANTHROPIC_API_KEY`.

### Verify without spending tokens

Always validate evidence collection first:

```powershell
.\.venv\Scripts\python.exe -m src.investigate_generic --alert-id '<ALERT_ID>' --evidence-only
```

Remove or revoke a key immediately if it is accidentally committed or exposed.


## Run

Evidence collection only:

```powershell
.\.venv\Scripts\python.exe -m src.investigate_generic --alert-id '<ALERT_ID>' --evidence-only
```

Assessment with the provider configured in `.env`:

```powershell
.\.venv\Scripts\python.exe -m src.investigate_generic --alert-id '<ALERT_ID>'
```

Always quote dotted Wazuh alert IDs in PowerShell. Reports are written to
`data/investigations/`; this directory is intentionally excluded from Git.

## Verify

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Repository layout

- `src/` — controlled Wazuh tools, normalization, correlation, LLM contracts, and reporting
- `tests/` — offline unit and contract tests
- `config/alert_scope.json` — local intake exclusions; it does not alter Wazuh rules
- `docs/` — architecture, operator, and data-contract documentation
- `.env.example` — placeholder-only configuration template

## Data and credential safety

Never commit `.env`, `.wazuh*.env`, `data/`, prompt audits, reports, raw alerts,
analyst worksheets, or benchmark evidence. Before publishing a fork, inspect the
staged file list and run a secret scanner. This source package does not include
live credentials or operational evidence.

See [architecture](docs/architecture.md), [operator runbook](docs/operator_runbook.md),
and [Wazuh tool layer](docs/wazuh_tool_layer.md) for further details.
