"""Analyst-readable report rendering for generic, cited LLM assessments."""
from __future__ import annotations

from datetime import datetime, timezone
from html import unescape
from pathlib import Path
import re
from typing import Any, Mapping

try:
    from .generic_response_guidance import build_response_proposals
except ImportError:
    from generic_response_guidance import build_response_proposals


def write_generic_report(packet: Mapping[str, Any], assessment: Mapping[str, Any] | None, model: Mapping[str, Any], path: Path, error: str | None = None) -> Path:
    """Write a bounded report without exposing raw telemetry or correlation GUIDs."""
    alert = _mapping(packet.get("alert"))
    entities = _mapping(packet.get("observed_entities"))
    seed_fields = _mapping(next((item.get("fields") for item in _list(packet.get("evidence")) if isinstance(item, Mapping) and item.get("relationship") == "seed_alert"), {}))
    hostname = entities.get("host") or seed_fields.get("host")
    model_name = f"{_text(model.get('provider'), 'not invoked')} / {_text(model.get('model'), 'not invoked')}"
    lines = [
        f"# Wazuh Investigation Report — {_text(alert.get('title'), 'Untitled alert')}", "",
        "## Case metadata", "",
        f"- Case ID: {_code(path.stem)}",
        f"- Generated (UTC): {_code(f'{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}')}",
        f"- Alert ID: {_code(_text(alert.get('alert_id'), 'not recorded'))}",
        f"- Assessment model: {_code(model_name)}",
        f"- Model invoked: {_code(str(bool(model.get('invoked'))).lower())}", "",
        "## Executive summary", "",
    ]
    _executive_summary(lines, assessment, alert, error)
    lines.extend([
        "## Alert overview", "",
        f"- Alert name: **{_text(alert.get('title'), 'not recorded')}**",
        f"- Timestamp (UTC): {_code(_text(alert.get('timestamp_utc'), 'not recorded'))}",
        f"- Wazuh rule level: {_code(_text(alert.get('severity'), 'not recorded'))}",
        f"- Hostname: {_code(_text(hostname, 'not recorded'))}",
        f"- Wazuh rule ID: {_code(_text(alert.get('rule_id'), 'not recorded'))}",
        f"- Source: {_code(_source_text(_mapping(alert.get('source'))))}", "",
    ])
    _mitre_section(lines, _mapping(_mapping(alert.get("source")).get("mitre")))
    chain = _process_chain(packet)
    if chain:
        lines.extend(["## Activity tree", "", "```text", *chain, "```", ""])
    _evidence_timeline(lines, packet)

    if assessment is None:
        lines.extend(["", "## Assessment", "", "No accepted model assessment is available."])
        if error:
            lines.append(f"Validation/provider result: {_code(error)}")
        return _write(path, lines)

    lines.extend(["", "## Assessment", "", f"- Assessment status: **{_text(assessment.get('assessment_status'), 'accepted')}**", ""])
    _narrative_section(lines, "What happened", assessment.get("what_happened"), level=3)
    claim = _mapping(assessment.get("alert_claim_assessment"))
    lines.extend(["### Alert claim assessment", "", f"- Status: **{_text(claim.get('status'))}** — {_text(claim.get('text'))} {_refs(claim.get('evidence_ids'))}", ""])
    hypotheses = _list(assessment.get("hypotheses"))
    lines.extend(["## Confidence rationale", "", "The confidence value is the model's bounded judgment, not a statistical probability.", ""])
    _narrative_section(lines, "Concern factors", [item for item in hypotheses if isinstance(item, Mapping) and item.get("type") == "possible_concern"], level=3)
    _narrative_section(lines, "Possible legitimate context", [item for item in hypotheses if isinstance(item, Mapping) and item.get("type") == "possible_legitimate_context"], level=3)
    _list_section(lines, "Evidence limitations", assessment.get("unknowns"), "No material packet limitation was selected.", level=3)
    flags = _list(assessment.get("quality_flags"))
    lines.extend(["## Key gaps and cautions", ""])
    _merged_cautions(lines, flags)
    lines.extend(["", "## Recommended analyst actions", ""])
    proposals = build_response_proposals(packet, assessment)
    if proposals:
        _action_checklists(lines, proposals)
    else:
        lines.append("No action selected by the model.")
    lines.append("")
    return _write(path, lines)


def _executive_summary(lines: list[str], assessment: Mapping[str, Any] | None, alert: Mapping[str, Any], error: str | None) -> None:
    if assessment is None:
        lines.extend(["> [!CAUTION]", "> **No accepted LLM assessment is available.**", f"> Validation/provider result: `{_text(error, 'not recorded')}`", ""])
        return
    verdict = _text(assessment.get("verdict"), "not assessed")
    callout = {"likely_benign": "NOTE", "inconclusive": "CAUTION", "suspicious_requires_review": "WARNING", "likely_malicious": "CAUTION"}.get(verdict, "NOTE")
    lines.extend([
        f"> [!{callout}]",
        f"> **Verdict:** {_verdict_label(verdict)} | **Confidence:** {_text(assessment.get('confidence'), 'not recorded')}/100 | **Wazuh rule level:** {_text(alert.get('severity'), 'not recorded')}",
    ])
    happened = next((item for item in _list(assessment.get("what_happened")) if isinstance(item, Mapping)), None)
    if happened:
        lines.append(f"> {_text(happened.get('text'))} {_refs(happened.get('evidence_ids'))}")
    question = _text(assessment.get("analyst_question"))
    if question:
        lines.append(f"> **Analyst focus:** {question}")
    lines.append("")


def _narrative_section(lines: list[str], title: str, value: Any, level: int = 2) -> None:
    lines.extend([f"{'#' * level} {title}", ""])
    items = _list(value)
    if not items:
        lines.extend(["No evidence-backed statement was selected.", ""])
        return
    for item in items:
        if isinstance(item, Mapping):
            lines.append(f"- {_text(item.get('text'))} {_refs(item.get('evidence_ids'))}")
    lines.append("")


def _list_section(lines: list[str], title: str, value: Any, fallback: str, level: int = 2) -> None:
    lines.extend([f"{'#' * level} {title}", ""])
    entries = [str(item) for item in _list(value) if isinstance(item, str) and item.strip()]
    lines.extend([f"- {item}" for item in entries] or [fallback])
    lines.append("")


def _detail_text(fields: Mapping[str, Any], count: Any, item: Mapping[str, Any]) -> str:
    labels = {"host": "Host", "user": "User", "process_name": "Process", "parent_process_name": "Parent", "target_process_name": "Target process", "registry_key": "Registry key", "registry_value": "Registry value", "file_path": "File", "source_ip": "Source IP", "destination_ip": "Destination IP", "destination_port": "Destination port", "domain": "Domain", "command_line": "Command", "decoded_command": "Decoded command", "service_name": "Service", "service_image_path": "Service image", "service_account": "Service account", "service_start_type": "Service start type", "service_type": "Service type", "vulnerability_cve": "Vulnerability", "vulnerability_package": "Affected package", "vulnerability_package_version": "Package version", "vulnerability_severity": "Vulnerability severity", "vulnerability_cvss": "CVSS"}
    parts = [f"{label}: {_code(fields[key])}" for key, label in labels.items() if fields.get(key) not in (None, "")]
    if isinstance(count, int) and count > 1:
        parts.append(f"Occurrences: {_code(count)}")
    if item.get("first_seen_utc") and item.get("last_seen_utc"):
        parts.append(f"Window: {_code(item['first_seen_utc'])} to {_code(item['last_seen_utc'])}")
    return "; ".join(parts)


def _evidence_timeline(lines: list[str], packet: Mapping[str, Any]) -> None:
    lines.extend(["## Evidence timeline", "", "| ID | Time (UTC) | Relationship | Activity | Evidence detail |", "| --- | --- | --- | --- | --- |"])
    for item in _list(packet.get("evidence")):
        if not isinstance(item, Mapping):
            continue
        fields = _mapping(item.get("fields"))
        activity = _first_display(fields, "process_name", "target_process_name", "service_name", "registry_key", "file_path", "domain", "destination_ip") or _text(item.get("summary"), "Observed event")
        detail = _first_detail(fields)
        lines.append("| " + " | ".join([
            _table_text(_text(item.get("id"), "E??")),
            _table_text(_text(item.get("timestamp_utc"), "not recorded")),
            _table_text(_text(item.get("relationship"), "related_activity").replace("_", " ")),
            _table_code(activity),
            _table_code(detail) if detail else "—",
        ]) + " |")
    lines.append("")


def _first_display(fields: Mapping[str, Any], *keys: str) -> str:
    return next((_display(fields[key]) for key in keys if fields.get(key) not in (None, "")), "")


def _first_detail(fields: Mapping[str, Any]) -> str:
    for key in ("decoded_command", "command_line", "registry_value", "file_path", "registry_key", "destination_ip", "domain"):
        if fields.get(key) not in (None, ""):
            return _display(fields[key])
    return ""


def _table_text(value: Any) -> str:
    return _display(value).replace("|", "\\|").replace("\n", " ")


def _table_code(value: Any) -> str:
    return _code(_table_text(value))


def _merged_cautions(lines: list[str], flags: list[Any]) -> None:
    if not flags:
        lines.append("No additional assessment caution was recorded.")
        return
    grouped: dict[str, dict[str, Any]] = {}
    for flag in flags:
        if not isinstance(flag, Mapping):
            continue
        code = _text(flag.get("code"), "other")
        entry = grouped.setdefault(code, {"messages": [], "refs": []})
        message = _text(flag.get("message"))
        if message and message not in entry["messages"]:
            entry["messages"].append(message)
        for ref in _list(flag.get("evidence_ids")):
            if isinstance(ref, str) and ref not in entry["refs"]:
                entry["refs"].append(ref)
    labels = {
        "unverified_operational_context": "Unverified operational context",
        "weak_temporal_link": "Weak temporal relationship",
        "weak_correlation_basis": "Weak correlation basis",
        "unverified_software_identity": "Unverified software identity",
    }
    for code, entry in grouped.items():
        message = entry["messages"][0] if len(entry["messages"]) == 1 else _merged_flag_message(code)
        lines.append(f"- **{labels.get(code, code.replace('_', ' ').title())}:** {message} {_refs(entry['refs'])}")


def _merged_flag_message(code: str) -> str:
    return {
        "unverified_operational_context": "Authorization, testing, expected behavior, or other operational context was considered but not independently collected.",
        "weak_temporal_link": "Some cited events are too far apart to establish one causal sequence.",
    }.get(code, "Multiple related cautions were consolidated for readability.")


def _action_checklists(lines: list[str], proposals: list[Any]) -> None:
    groups = (
        ("Investigation", {"investigate"}),
        ("Context validation", {"validate_context"}),
        ("Evidence preservation", {"preserve_evidence"}),
        ("Escalation", {"escalate"}),
        ("Response considerations", {"consider_response"}),
    )
    for title, categories in groups:
        selected = [item for item in proposals if isinstance(item, Mapping) and item.get("category") in categories]
        if not selected:
            continue
        lines.extend([f"### {title}", ""])
        for proposal in selected:
            target = proposal.get("target")
            target_text = f" Target: {_code(target)}." if target else ""
            approval = " Human approval required." if proposal.get("requires_human_approval") else ""
            priority = str(proposal.get("priority", "medium")).title()
            lines.append(f"- [ ] **{priority}:** {proposal['action']} {_refs(proposal.get('evidence_ids'))}")
            lines.append(f"  - **Why:** {proposal['reason']}{target_text}{approval} Recommendation only; no action was executed.")
        lines.append("")


def _mitre_section(lines: list[str], mitre: Mapping[str, Any]) -> None:
    ids = _strings(mitre.get("id"))
    techniques = _strings(mitre.get("technique"))
    tactics = _strings(mitre.get("tactic"))
    if not (ids or techniques or tactics):
        return
    lines.extend(["## Source-provided MITRE ATT&CK context", "", "These mappings came from the Wazuh alert and are detection metadata, not independent proof of malicious activity.", ""])
    if ids:
        lines.append("- Technique IDs: " + ", ".join(_code(item) for item in ids))
    if techniques:
        lines.append("- Techniques: " + ", ".join(_code(item) for item in techniques))
    if tactics:
        lines.append("- Tactics: " + ", ".join(_code(item) for item in tactics))
    lines.append("")


def _process_chain(packet: Mapping[str, Any]) -> list[str]:
    evidence = [item for item in _list(packet.get("evidence")) if isinstance(item, Mapping)]
    seed = next((item for item in evidence if item.get("relationship") == "seed_alert"), None)
    if not seed:
        return []
    seed_fields = _mapping(seed.get("fields"))
    if not seed_fields.get("process_name"):
        return []
    parent = next((item for item in evidence if item.get("relationship") == "parent_process_origin" and _mapping(item.get("fields")).get("process_name")), None)
    children = [item for item in evidence if item.get("relationship") == "direct_child_process" and _mapping(item.get("fields")).get("process_name")]
    lines: list[str] = []
    if parent:
        parent_fields = _mapping(parent.get("fields"))
        if parent_fields.get("parent_process_name"):
            lines.append(f"{_display(parent_fields.get('parent_process_name'))} [context from {_text(parent.get('id'), 'E??')}]")
            lines.append(f"└── {_display(parent_fields.get('process_name'))} [{_text(parent.get('id'), 'E??')}]" )
            seed_prefix = "    └── "
            child_prefix = "        "
        else:
            lines.append(f"{_display(parent_fields.get('process_name'))} [{_text(parent.get('id'), 'E??')}]" )
            seed_prefix = "└── "
            child_prefix = "    "
    elif seed_fields.get("parent_process_name"):
        lines.append(f"{_display(seed_fields.get('parent_process_name'))} [parent observed in {_text(seed.get('id'), 'E??')}]" )
        seed_prefix = "└── "
        child_prefix = "    "
    else:
        seed_prefix = ""
        child_prefix = ""
    lines.append(f"{seed_prefix}{_display(seed_fields.get('process_name'))} [{_text(seed.get('id'), 'E??')}, seed]")
    for index, child in enumerate(children):
        branch = "└── " if index == len(children) - 1 else "├── "
        child_fields = _mapping(child.get("fields"))
        lines.append(f"{child_prefix}{branch}{_display(child_fields.get('process_name'))} [{_text(child.get('id'), 'E??')}]" )
    if len(lines) < 2:
        return []
    return lines


def _verdict_label(value: Any) -> str:
    return {
        "likely_benign": "LIKELY BENIGN",
        "inconclusive": "INCONCLUSIVE",
        "suspicious_requires_review": "SUSPICIOUS — REQUIRES REVIEW",
        "likely_malicious": "LIKELY MALICIOUS",
    }.get(_text(value), _text(value, "NOT ASSESSED").replace("_", " ").upper())


def _refs(value: Any) -> str:
    return " ".join(f"[{item}]" for item in _list(value) if isinstance(item, str))


def _source_text(source: Mapping[str, Any]) -> str:
    return " / ".join(str(source[key]) for key in ("provider", "channel", "event_id") if source.get(key) not in (None, "")) or "not recorded"


def _strings(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return [str(item).strip() for item in _list(value) if str(item).strip()]


def _write(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return path


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any, fallback: str = "") -> str:
    return _display(value) if value not in (None, "") else fallback


def _code(value: Any) -> str:
    text = _display(value)
    return f"``{text}``" if "`" in text else f"`{text}`"


def _display(value: Any) -> str:
    """Make Wazuh's retained XML/JSON escaping readable without changing evidence."""
    text = unescape(str(value))
    retained_escapes = '\\"' in text or bool(re.search(r"[A-Za-z]:\\\\", text)) or bool(re.match(r"^[^\\]+\\\\[^\\]+$", text))
    if retained_escapes:
        text = text.replace('\\"', '"').replace("\\\\", "\\")
    return text
