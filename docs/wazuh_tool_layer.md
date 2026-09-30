# Wazuh / OpenSearch tool layer

`src/wazuh_tools.py` is the sole backend boundary for the investigation agent.
The LLM supplies only a tool name and schema-validated arguments; it cannot send
raw Wazuh API requests or OpenSearch DSL.

## Configuration

Copy `.env.example` into your local secret manager or `.env` and set real
credentials. Use a read-only Indexer account. `WAZUH_VERIFY_TLS` should stay
`true` outside a disposable lab.

For this lab, `.wazuh.local.env` contains the current tunnel configuration and
is Git-ignored. Rotate the OVA's default `admin` password before treating the
lab as anything other than disposable; then update the local file. The loader
never overrides Wazuh environment variables supplied by the shell or deployment
platform.

## Run a real investigation

Configure `LLM_PROVIDER` and `LLM_MODEL` in a local environment file, then seed
only with an alert ID returned by Wazuh:

```powershell
.\.venv\Scripts\python.exe -m src.investigate_wazuh --alert-id <WAZUH_ALERT_ID>
```

The runner first retrieves that exact alert, creates its initial evidence record,
then invokes the selected model only for strict next-action JSON. A model cannot
access credentials or APIs directly. Reports are saved under
`data/investigations/` and are excluded from Git.

## Response proposals

The decision schema also includes `isolate_host`, `block_ip`, and `disable_user`.
They are simulations only: an observed target is required, the output records an
approval-required proposal, and no endpoint, firewall, identity provider, or
Wazuh active-response command is contacted. This creates an auditable separation
between investigation recommendation and real-world containment.

## Tool calls

```python
from src.wazuh_tools import WazuhConfig, WazuhToolLayer

tools = WazuhToolLayer(WazuhConfig.from_env())
high = tools.get_alerts(severity=12)
one = tools.get_alert_by_id("abc-1")
processes = tools.get_host_process_activity("workstation-01")
dns = tools.get_dns_activity("workstation-01")
logs = tools.search_logs({
    "filters": [{"field": "destination.ip", "operator": "equals", "value": "203.0.113.10"}],
    "hours": 24,
})
```

Each response has this stable shape:

```json
{"ok": true, "tool": "get_alerts", "data": [{"alert_id": "...", "host": "...", "rule": {}}], "meta": {"count": 1, "total": 1, "truncated": false}, "error": null}
```

Failure returns `ok: false` with a safe `error.code` (`validation_error`,
`configuration_error`, or `backend_error`). The layer does not raise backend
details into agent control flow.

## Backend requests

Alert retrieval posts a bounded `_search` request to:

```
POST https://INDEXER:9200/wazuh-alerts-*/_search
```

The Wazuh manager example authenticates with:

```
POST https://MANAGER:55000/security/user/authenticate
GET  https://MANAGER:55000/agents?status=active&limit=100
```

The manager API is deliberately not used as a substitute for event search:
alerts and endpoint telemetry are retrieved from the Wazuh Indexer/OpenSearch
alert index. Field mappings vary by Wazuh decoder/module; extend the explicit
`_SAFE_FIELD_NAMES` allowlist only after confirming a field in your index.

## Phase 2 guarded loop

`src/agent_loop.py` replaces dynamic `getattr` tool execution. It accepts only a
strict decision object, confirms every argument was returned by earlier evidence,
hashes the canonical action to block repeats, and saves serialisable state after
each execution. Seed an investigation with the alert that triggered it, then run
the agent; it may only pivot using values from that alert or later tool results.

## Phase 3 evidence interpretation

`src/reasoning.py` turns normalized Wazuh output into traceable facts and MITRE
ATT&CK technique candidates. Native `rule.mitre` fields from Wazuh are preserved
as authoritative mappings. Only when that field is absent does the interpreter
apply deterministic fallback candidates, and each stores the supporting evidence
ID plus its source. The fallback currently recognizes observed PowerShell (`T1059.001`),
encoded or obfuscated commands (`T1027`), Office application indicators
(`T1204.002`), and DNS activity (`T1071.004`). A mapping is a candidate based on
the event data—not a declaration that a host is compromised. Extend the mapping
table only with a documented detector and test case.
