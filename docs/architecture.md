# AI SOC Investigator architecture

## Purpose

AI SOC Investigator is a local, evidence-grounded SOC assistant for small teams
using Wazuh. The goal is not to replace an analyst or modify Wazuh rules. The
goal is to take a real Wazuh alert, collect relevant supporting telemetry,
ask an LLM to reason over only that evidence, and produce a readable
investigation report with cited recommendations.

## Current V1 workflow

1. Analyst selects a Wazuh alert ID.
2. The tool retrieves the alert directly from Wazuh/OpenSearch.
3. The alert is normalized into a stable schema using only observed fields.
4. Local intake scope rejects configured out-of-scope alert categories, such as
   vulnerability detector, SCA, CIS benchmark, and CVE-style alerts.
5. The entity planner extracts useful pivots from the seed alert, such as host,
   agent, process GUID, parent process GUID, target process GUID, registry key,
   file path, IP, domain, and authentication context.
6. The collection executor queries Wazuh/OpenSearch through controlled Python
   tools. The LLM never queries Wazuh directly.
7. The evidence packet is built from the seed alert plus bounded related
   observations. The packet is compact, source-traceable, deduplicated, and
   limited to analyst-relevant fields.
8. If the run is not evidence-only, one LLM assessment prompt is created from
   the compact evidence packet.
9. The LLM must return strict JSON under the generic assessment contract.
10. Python validates the response. Accepted assessments become reports;
    invalid or unsupported assessments are withheld and reported as rejected.
11. Prompt, response, packet, report, model name, and usage metadata are saved
    for audit and replay.

## Main components

| Component | Responsibility |
| --- | --- |
| Wazuh tool layer | Safe Python wrappers around Wazuh/OpenSearch queries. |
| Alert normalizer | Converts different Wazuh alert shapes into one stable alert schema without inventing values. |
| Alert scope | Locally excludes alert families that are outside V1 investigation scope. This does not change Wazuh. |
| Entity planner | Builds bounded correlation plans from exact seed-alert entities. |
| Evidence collector | Executes controlled searches for process lineage, parent/target process origin, registry/file pivots, IP/domain pivots, and authentication context. |
| Evidence packet builder | Produces compact, source-traceable evidence for the model and report. |
| LLM assessment layer | Performs bounded reasoning, verdict selection, confidence scoring, hypotheses, and recommendations. |
| Deterministic validator | Enforces schema, citations, verdict requirements, confidence gates, and recommendation safety. |
| Report renderer | Converts accepted or rejected results into an analyst-readable Markdown report. |
| Offline evaluator | Replays saved responses against the current contract without calling an LLM. |

## Evidence and correlation approach

V1 uses entity-based correlation rather than a separate dossier for every Wazuh
rule. The seed alert provides exact entities. The tool then pivots only on
safe, observed values from that alert.

Examples:

- Process alerts may correlate by process GUID, parent process GUID, target
  process GUID, and host or agent.
- Registry alerts may correlate by exact registry key and related process
  context.
- File alerts may correlate by exact file path and process context.
- Network and DNS alerts may correlate by exact IP or domain on the same host.
- Authentication alerts may correlate by user and source IP when identity
  context is present.

The packet labels relationships such as `seed_alert`, `same_process`,
`direct_child_process`, `parent_process_origin`, `target_process_origin`,
`same_registry_key`, `same_file_path`, `same_ip`, `same_domain`, and
`authentication_context`.

Relationship labels are not verdicts. For example, `same_hash` means shared
file identity only; it does not prove a common process chain or causation.

## LLM role

The LLM is responsible for:

- explaining what happened in plain analyst language;
- assessing whether the Wazuh alert claim is supported, partially supported,
  unsupported, or not assessable from collected evidence;
- giving a bounded verdict;
- assigning a confidence score;
- describing possible legitimate context and possible concern;
- stating unknowns;
- recommending next analyst actions.

The LLM is not allowed to:

- query Wazuh or raw APIs;
- invent hosts, users, commands, IPs, hashes, files, registry keys, or evidence
  IDs;
- treat the Wazuh alert title as proof;
- claim a command succeeded unless outcome telemetry exists;
- recommend containment actions unless strict response conditions are met.

## Verdicts

The accepted verdict list is:

- `likely_benign`
- `inconclusive`
- `suspicious_requires_review`
- `likely_malicious`

Most real investigations should land in `inconclusive` or
`suspicious_requires_review` unless the collected evidence is strong enough to
support a clearer benign or malicious conclusion.

## Confidence calculation

In the generic V1 flow, confidence is selected by the LLM as an integer from
0 to 100, but it is not accepted blindly. Python validates that the confidence
is compatible with the verdict and evidence.

Current confidence rules:

- Confidence must be an integer from 0 to 100.
- `likely_benign` requires confidence of at least 35.
- `likely_benign` requires at least two independent cited observations and at
  least one stated evidence limitation.
- `likely_benign` confidence above 65 is rejected when the assessment uses
  unverified operational-context assumptions.
- `likely_malicious` requires confidence of at least 70.
- `likely_malicious` requires at least two cited concern sources.
- `consider_response` recommendations are allowed only when the verdict is
  `likely_malicious` and confidence is at least 70.

So confidence is best understood as a model judgment constrained by evidence
rules, not a statistical probability.

## When an alert is rejected before assessment

An alert is not investigated when:

- the alert ID cannot be found;
- the alert matches the local out-of-scope configuration;
- the normalized alert lacks enough identity to build a safe collection scope,
  such as both host and agent identity being unavailable;
- required Wazuh/OpenSearch access fails.

Out-of-scope examples in the current configuration include:

- vulnerability detector alerts;
- SCA alerts;
- CIS Benchmark alerts;
- CVE-title alerts.

These exclusions apply only to this tool's intake. Wazuh still keeps and shows
the alerts.

## When an LLM assessment is rejected

The model response is rejected and withheld when any of these occur:

- response is not valid JSON;
- response has missing, extra, or incorrectly named fields;
- verdict is outside the allowed list;
- confidence is not an integer from 0 to 100;
- cited evidence IDs do not exist in the packet;
- required cited sections are missing;
- `what_happened` contains unsupported interpretation instead of observation;
- the model claims a completed outcome from command-line intent alone;
- a hypothesis uses unbounded language or unsupported facts;
- `likely_benign` or `likely_malicious` fails its evidence and confidence
  requirements;
- recommendation targets do not exactly match observed evidence values;
- recommendation text contains concrete identifiers absent from evidence;
- response-action wording appears outside the `consider_response` category;
- `consider_response` lacks human or analyst approval language;
- the report generated from the result does not pass offline quality checks.

Rejected does not mean the alert is benign. It means the model output was not
safe or well-supported enough to become the analyst-facing conclusion.

## Accepted with flags

Some assessments are useful but still need explicit caution. These are accepted
with flags, not silently promoted to clean conclusions.

Examples:

- the model uses unverified operational context, such as "test", "approved",
  "known", "controlled", or "expected";
- a hypothesis relies on weak correlation, such as same-hash identity only;
- cited events are too far apart in time to imply one causal sequence;
- software identity or ownership is inferred from a path or product-looking
  string without signer or provenance evidence.

The report shows these cautions directly.

## Recommendations and response actions

The LLM may write up to three recommendations. Each recommendation must include:

- category;
- action;
- reason;
- evidence IDs;
- optional exact observed target;
- priority.

Allowed categories are:

- `investigate`
- `validate_context`
- `preserve_evidence`
- `escalate`
- `consider_response`

`consider_response` is recommendation-only. The current V1 tool does not isolate
hosts, block IPs, disable accounts, delete files, or perform active response.

## Auditability

Every run saves:

- normalized alert;
- evidence packet;
- model provider and model name;
- exact prompt;
- exact model response;
- parsed assessment or rejection error;
- generated report;
- usage and estimated cost where available.

This allows offline replay against the current contract without spending more
tokens.

## Current limitations

- V1 is strongest for behavioral Wazuh alerts with usable host, process,
  registry, file, network, DNS, or authentication entities.
- The tool does not prove business authorization or user intent unless that
  evidence is present.
- Confidence is evidence-constrained model judgment, not mathematical risk.
- No active response is executed in V1.
- Benchmarking is still required before calling the project release-ready.

## V1 success criteria

V1 should be considered ready only when:

- normalized alert intake works across materially different in-scope Wazuh
  alerts;
- evidence packets contain no invented fields;
- rejected model outputs are safely withheld;
- accepted reports cite traceable evidence;
- recommendations are specific and evidence-backed;
- the offline quality gate passes;
- analyst review shows the reports are useful and not misleading across the
  agreed benchmark set.
