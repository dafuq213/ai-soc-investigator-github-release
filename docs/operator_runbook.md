# V1 operator runbook

## What the system does

`investigate_generic` is the active V1 path:

```text
Wazuh alert -> normalized alert -> entity-derived enrichment -> bounded evidence packet
            -> selected LLM -> schema/citation validation -> report
```

The LLM does not receive Wazuh credentials, an API URL, an OpenSearch query
language, or tools. It receives bounded case evidence and must emit one strict
JSON object. Any unavailable provider, malformed JSON, unknown evidence ID, or
unsupported claim produces an evidence-only `inconclusive` report.

## Configuration

Keep Wazuh credentials in the Git-ignored `.wazuh.local.env`. Select a model in
the Git-ignored `.env`. The local configuration loader reads both files without
overriding variables already supplied by the environment.

```env
LLM_PROVIDER=ollama
LLM_MODEL=llama3.2
OLLAMA_BASE_URL=http://localhost:11434
```

Supported providers are `ollama`, `openai`, `anthropic`, `gemini`, `claude_cli`,
and `gemini_cli`. API providers require their respective API key. Use a model
only after you have deliberately configured it; `--use-llm` can incur API cost
for API-backed providers.

## Run a case

First locate an exact alert ID in Wazuh Dashboard, or select a locally unseen
one without calling an LLM:

```powershell
.\.venv\Scripts\python.exe -m src.unseen_alert_selector --min-severity 3 --max-severity 16
```

Then run either mode. Quote dotted Wazuh IDs in PowerShell so they are not
rounded before Python receives them:

```powershell
# Safe connectivity and evidence check. Does not call an LLM.
.\.venv\Scripts\python.exe -m src.investigate_generic --alert-id '<ALERT_ID>' --evidence-only

# Full verified assessment with your configured provider.
.\.venv\Scripts\python.exe -m src.investigate_generic --alert-id '<ALERT_ID>' --case-id '<CASE_ID>'
```

Artifacts are written to `data/investigations/<CASE_ID>.json` and `.md`. The
JSON keeps the normalized alert, compact evidence packet, saved model response
audit, and validation result. The Markdown report renders only accepted,
evidence-cited reasoning.

## Response boundary

V1 never executes a containment action. `isolate_host`, `block_ip`, and
`disable_user` remain simulations/approval-required proposals. Host isolation
and IP blocking need cited network evidence; unsupported model recommendations
reject the complete model assessment instead of being shown to an operator.

## Evaluation gate

Run the contract-quality harness:

```powershell
.\.venv\Scripts\python.exe -m src.generic_benchmark
```

The included cases prove contract mechanics only. Do not call the system
production-ready until there are at least 30 analyst-reviewed cases spanning
process, authentication, registry/file/network, and system/application alert
families, and all release gates are true. Every review record must include:

- case ID, alert family, and evidence packet;
- the captured audited model response;
- analyst verdict/reasoning review;
- cited-evidence correctness and whether any response recommendation was unsafe.

This keeps evaluation reproducible and avoids silently grading a model against
its own output.
