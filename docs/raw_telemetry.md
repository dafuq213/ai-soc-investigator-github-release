# Raw telemetry for parent-process validation

## Why alerts are insufficient

The alert index contains events that matched a Wazuh rule. A legitimate parent
process, such as `chrome.exe`, normally does not generate an alert. An
investigation that searches only `wazuh-alerts-*` can therefore see a child
PowerShell alert but fail to retrieve the ordinary parent process that created
it.

## Required data source

Configure Wazuh to retain and index raw/archive events, then set the resulting
index pattern locally:

```env
WAZUH_TELEMETRY_INDEX=wazuh-archives-*
```

The exact archive pipeline depends on the installed Wazuh version. In general,
the manager must retain all decoded events and the shipper must send the archive
stream to the indexer. Confirm the actual index name in your Wazuh Indexer
before setting this value; do not assume the example pattern exists.

## Verify safely

```powershell
.\.venv\Scripts\python.exe -c "from src.wazuh_tools import WazuhConfig,WazuhToolLayer; print(WazuhToolLayer(WazuhConfig.from_env()).get_telemetry_status())"
```

When configured, process, network, DNS, host-activity, and authentication
enrichment tools query this telemetry index. If it is absent, their result
metadata states `alerts_fallback`, making the evidence limitation explicit.

## Investigation use

For a browser-to-PowerShell chain, retrieve and report the parent image and
command line; decoded PowerShell behavior; child processes; process-linked
network/DNS activity; and relevant file activity. Neither a browser parent nor
an encoded command is a verdict. The report should explain observed behavior,
give benign alternatives, ask whether it was expected, and recommend more
collection if it was not.
