# Product contracts: investigation V1

## Product boundary

The product is an AI-assisted Wazuh investigator for organizations without a
dedicated SOC. It gathers and correlates evidence, asks an LLM for structured
reasoning, verifies every claim against evidence, and provides response
guidance. V1 never executes containment.

Allowed verdicts are `expected_activity`, `inconclusive`, and
`suspicious_requires_review`. A verdict of `malicious` is intentionally out of
scope until a labelled evaluation corpus demonstrates calibrated performance.

## Shared case contract

Every case must retain:

- a seed alert and canonical evidence IDs;
- extracted entities: hosts, users, process GUIDs, IPs, domains, and hashes;
- a timestamped timeline;
- tool history and raw normalized evidence;
- claims with supporting evidence IDs;
- benign alternatives, unknowns, and contradictory evidence;
- a verdict, confidence inputs, and response recommendations.

Every user-visible factual claim must reference one or more evidence IDs. A
claim without a valid citation is rejected by the verifier. Recommendations are
advice only and always include reason, risk, and approval requirement.

## Contract 1: suspicious or encoded PowerShell

### Seed signals

- Sysmon Process Create with `powershell.exe`, `pwsh.exe`, `-enc`,
  `-EncodedCommand`, `-NoProfile`, hidden-window flags, or a Wazuh PowerShell
  rule.

### Required evidence collection

- process image, command line, ProcessGUID, PID, user, timestamp, hash;
- parent image, parent command line, ParentProcessGUID, ParentPID;
- process children and related process activity keyed by ProcessGUID;
- associated network and DNS activity keyed by ProcessGUID and a bounded time
  window;
- downloaded/executed file activity where telemetry provides it.

### Correlation keys

Prefer `ProcessGUID` and `ParentProcessGUID`; use PID only with host and a
bounded time window. Do not construct a process relationship from process name
alone.

### Suspicious indicators

- Office application or browser spawning PowerShell;
- encoded command followed by network activity, LOLBins, or execution from
  user-writable locations;
- external destination with adverse reputation once a threat-intelligence tool
  is added;
- child `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, or an unexpected executable.

### Benign alternatives

- approved administrative, deployment, endpoint-management, login, or internal
  automation scripts;
- documented change activity;
- known parent process and expected command pattern.

### Verdict rules

- `expected_activity`: a benign explanation is directly supported by observed
  evidence or an approved allowlist/change record. When that context is absent,
  the report must explain the observed behavior, ask the analyst whether it was
  expected, and retain `inconclusive` as the default.
- `inconclusive`: critical parent, child, network, user, or change-context
  evidence is missing.
- `suspicious_requires_review`: multiple independent suspicious indicators are
  supported and no comparable benign explanation is supported.

### Allowed V1 guidance

Collect parent/child/network evidence; preserve command line and host context;
recommend temporary host isolation only when evidence supports active external
communication or a high-risk execution chain.

## Contract 2: suspicious process execution chain

### Seed signals

- Sysmon Process Create or Wazuh rule indicating an unusual parent-child
  relationship, LOLBin use, or execution from suspicious locations.

### Required evidence collection

- complete parent and child relationships using ProcessGUID;
- image, command line, user, hash, working directory, and timestamps;
- network/DNS activity for each relevant process;
- file creation/execution events when available.

### Correlation keys

`ProcessGUID`, `ParentProcessGUID`, host, and timestamp are mandatory for a
process tree. Hash is an entity, not proof of maliciousness without an approved
reputation source.

### Suspicious indicators

- Office -> script interpreter -> LOLBin chain;
- child executable from Temp, Downloads, or a user profile;
- parent/child sequence followed by external communication;
- signed Windows binary used with an unusual command line.

### Benign alternatives

- software installer/updater;
- documented automation or developer tooling;
- expected endpoint-management or remote-support software.

### Verdict rules and guidance

Use the shared verdict rules. Recommendations may include preserving the file
and command line, checking other hosts for the hash, or isolating the host only
when the verified chain and impact justify it.

## Contract 3: authentication anomaly or brute force

### Seed signals

- repeated failed logins, invalid-user events, account lockouts, or a success
  after repeated failures.

### Required evidence collection

- user/account, source IP, target system, authentication type, failure reason,
  timestamps, and successful logins;
- event counts over a bounded window;
- prior behavior for the same user/source/target where telemetry is retained;
- service-account and password-change context when available.

### Correlation keys

Group by user, source IP, target, authentication type, and time window. A raw
failure count without these dimensions is insufficient.

### Suspicious indicators

- concentrated failures from one source followed by successful authentication;
- attempts against many accounts from one source;
- unusual source geography or target system once supported by verified data;
- privileged account involvement.

### Benign alternatives

- stale application/service-account credentials;
- password change not propagated to an application;
- expected administrative testing or VPN/login issues.

### Verdict rules and guidance

Use the shared verdict rules. Guidance may include validating the account owner,
resetting credentials, revoking active sessions, or blocking a confirmed abusive
source. It must state the operational risk and require approval.

## V1 evaluation gates

Before describing V1 as useful, the evaluation corpus must contain at least 30
analyst-labelled cases across these three contracts. It must measure verdict
accuracy, evidence citation accuracy, false-positive rate, unsupported-claim
rate, tool-call relevance, confidence calibration, and unsafe-response rate.

Non-negotiable release gates:

- zero user-visible unsupported claims in the held-out corpus;
- zero unsafe containment recommendations in the held-out corpus;
- every verdict cites evidence and lists material unknowns;
- every confidence value is explainable from recorded confidence inputs.
