"""Render a compact analyst report from verified, bounded case material."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

try:
    from .assessment import VerifiedAssessment
    from .case_models import InvestigationCase
    from .confidence import calculate_confidence
    from .response_advisor import advise
    from .evidence_interpretation import EvidenceInterpretation
    from .assessment_dossier import build_dossier
except ImportError:
    from assessment import VerifiedAssessment
    from case_models import InvestigationCase
    from confidence import calculate_confidence
    from response_advisor import advise
    from evidence_interpretation import EvidenceInterpretation
    from assessment_dossier import build_dossier


MAX_EVIDENCE_ITEMS = 8
MAX_NARRATIVE_ITEMS = 3
MAX_UNKNOWNS = 4
MAX_ACTIONS = 3

_PROFILE_LABELS = {
    "windows_sysmon_process": "Sysmon process activity",
    "windows_sysmon_network": "Sysmon network activity",
    "windows_sysmon_image_load": "Sysmon image-load activity",
    "windows_sysmon_process_access": "Sysmon process-access activity",
    "windows_sysmon_file": "Sysmon file activity",
    "windows_sysmon_registry": "Sysmon registry activity",
    "windows_sysmon_dns": "Sysmon DNS activity",
}


def write_verified_report(case: InvestigationCase, assessment: VerifiedAssessment, path: str | Path, interpretation: EvidenceInterpretation | None = None) -> Path:
    """Write an analyst-facing report with explicit per-section bounds.

    The report is not a raw-evidence export. Evidence IDs make each concise
    statement traceable; the case JSON remains the detailed audit record.
    """
    path = Path(path)
    dossier = build_dossier(case)
    trigger = dossier.get("trigger", {})
    seed = case.evidence[0] if case.evidence else None
    confidence = calculate_confidence(assessment)
    title = _text(trigger.get("title")) or "Wazuh alert investigation"
    host = _text(seed.record.get("host") if seed else None) or "not recorded"
    timestamp = _text(seed.timestamp if seed else None) or "not recorded"
    severity = trigger.get("severity") if trigger.get("severity") is not None else "not recorded"
    lines = [f"# Investigation — {title}", "", "## Case snapshot", ""]
    lines.extend([
        f"- Case ID: `{case.case_id}`",
        f"- Alert ID: `{case.seed_alert_id}`",
        f"- Host / time (UTC): `{host}` / `{timestamp}`",
        f"- Severity / verdict / confidence: `{severity}` / `{assessment.verdict}` / `{confidence.score:.0%}`",
        f"- Assessment state: `{assessment.status}`",
    ])
    lines.extend(_model_metadata_lines(case))

    lines.extend(["", "## Detection context", ""])
    lines.extend([
        f"- Wazuh alert: {title} (rule `{trigger.get('rule_id') or 'not recorded'}`, trigger `{trigger.get('evidence_id') or 'not recorded'}`).",
    ])
    claim = dossier.get("alert_claim")
    if isinstance(claim, Mapping) and claim.get("text"):
        lines.append(f"- Alert-claim status: `{claim.get('status', 'not recorded')}` — {claim['text']}")
    mitre = trigger.get("mitre")
    if isinstance(mitre, Mapping) and mitre:
        lines.append(f"- Wazuh MITRE metadata: `{_compact_value(mitre, 180)}`")

    lines.extend(["", "## Observed evidence", ""])
    profile_observation = dossier.get("profile_observation")
    if isinstance(profile_observation, Mapping):
        fields = profile_observation.get("fields")
        if isinstance(fields, Mapping) and fields:
            selected = "; ".join(
                f"{str(key).replace('_', ' ')}={_compact_value(value, 120)}"
                for key, value in list(fields.items())[:7]
            )
            lines.append(f"- Seed event (Sysmon Event ID {profile_observation.get('event_id', 'unknown')}): {selected}. Evidence: `{trigger.get('evidence_id') or 'not recorded'}`.")
    cards = dossier.get("activity_cards", [])
    if cards:
        for card in cards[:MAX_EVIDENCE_ITEMS]:
            lines.append(_card_line(card))
    else:
        lines.append("- No reduced activity cards were available from the collected telemetry.")
    decoded = [item for item in case.evidence if item.event_type == "decoded_powershell"]
    for item in decoded[:1]:
        command = _compact_value(item.record.get("decoded_command"), 360)
        lines.append(f"- Decoded command evidence `{item.evidence_id}` — `{command}`. Source: {item.record.get('source_evidence_id')}.")
        for behavior in item.record.get("observed_behavior", [])[:2]:
            lines.append(f"  - Observed command behavior: {behavior}")
        if item.record.get("embedded_null_count"):
            lines.append(f"  - Decode note: {item.record['embedded_null_count']} embedded NUL character(s) were removed only for readable rendering.")

    guidance = assessment.investigation_guidance or {}
    sections = guidance.get("sections") if isinstance(guidance, Mapping) else None
    if isinstance(sections, Mapping):
        lines.extend(["", "## What happened", ""])
        lines.extend(_judgment_section_lines(sections.get("what_happened"), "No cited narrative was accepted."))
        lines.extend(["", "## Wazuh claim versus confirmed evidence", ""])
        lines.extend(_judgment_section_lines(sections.get("alert_claim_assessment"), "No cited claim comparison was accepted."))
        lines.extend(["", "## Why it may be legitimate", ""])
        lines.extend(_judgment_section_lines(sections.get("reassuring_factors"), "No cited reassuring factor was selected."))
        lines.extend(["", "## Why it may be suspicious", ""])
        lines.extend(_judgment_section_lines(sections.get("concern_factors"), "No cited concern factor was selected."))

    lines.extend(["", "## Assessment", ""])
    if assessment.status == "accepted":
        verification = guidance.get("claim_verification") if isinstance(guidance, Mapping) else None
        if isinstance(verification, Mapping) and verification.get("text"):
            lines.append(f"- Model-selected claim verification: `{verification.get('status', 'not recorded')}`.")
        rationale = guidance.get("confidence_rationale") if isinstance(guidance, Mapping) else None
        if isinstance(rationale, str) and rationale:
            lines.append(f"- {rationale}")
        if isinstance(sections, Mapping):
            lines.extend(_judgment_section_lines(sections.get("competing_hypotheses"), "No competing hypothesis was selected from the evidence."))
        if assessment.narrative:
            lines.extend(f"- {item['text']} Evidence cards: {', '.join(item['card_ids'])}." for item in assessment.narrative[:MAX_NARRATIVE_ITEMS])
        if assessment.accepted_claims:
            lines.extend(f"- Verified finding: {_claim_summary(claim)} Evidence: {', '.join(claim.evidence_ids)}." for claim in assessment.accepted_claims[:2])
        if not assessment.narrative and not assessment.accepted_claims:
            lines.append("- No additional finding was accepted beyond the observed evidence and stated limitations.")
    elif interpretation and interpretation.status == "accepted" and interpretation.items:
        lines.append("- No LLM assessment was accepted. The following is a bounded explanation of observed evidence only, not proof of intent, compromise, or execution success.")
        lines.extend(f"- {item['text']} Source: {item['evidence_id']}." for item in interpretation.items[:2])
    else:
        lines.append("- No model assessment was accepted; use the observed evidence and stated gaps for analyst triage.")
        review = assessment.quality_review or {}
        if assessment.status == "qa_revision_required" and isinstance(review, Mapping):
            changes = review.get("required_changes", [])
            detail = changes[0] if isinstance(changes, list) and changes and isinstance(changes[0], str) else "QA requested revision."
            lines.append(f"- Assessment withheld by QA: {detail}")

    lines.extend(["", "## Evidence gaps and alternatives", ""])
    if assessment.status == "accepted" and assessment.benign_alternatives:
        lines.extend(f"- Alternative: {item}" for item in assessment.benign_alternatives[:2])
    # Collection gaps are deterministic facts.  Include them even when a
    # model was skipped or rejected, otherwise an evidence-only report can
    # misleadingly omit a missing parent or absent network result.
    deterministic_unknowns = [item.get("text") for item in dossier.get("unknown_options", []) if isinstance(item, Mapping) and isinstance(item.get("text"), str)]
    limitations = list(dict.fromkeys([*assessment.unknowns, *deterministic_unknowns, *_collection_limitations(case)]))
    for item in limitations[:MAX_UNKNOWNS]:
        lines.append(f"- Limitation: {item}")
    if not limitations and not (assessment.status == "accepted" and assessment.benign_alternatives):
        lines.append("- No explicit limitations were recorded.")

    lines.extend(["", "## Analyst decision and next steps", ""])
    actions = _actions(assessment, confidence.score)
    if actions:
        lines.extend(f"- `{action}`: {reason} Risk: {risk} Approval required." for action, reason, risk in actions[:MAX_ACTIONS])
    else:
        lines.append("- No response action is supported by the accepted evidence.")
    guidance = assessment.investigation_guidance or {}
    next_check = guidance.get("next_check") if isinstance(guidance, Mapping) else None
    if assessment.status == "accepted" and isinstance(next_check, str) and next_check:
        lines.append(f"- Priority evidence check: {next_check}")
    lines.extend(_targeted_collection_steps(limitations))

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _profile_lines(case: InvestigationCase) -> list[str]:
    profiles = case.correlations.get("telemetry_profiles", []) if isinstance(case.correlations, Mapping) else []
    if not profiles:
        return ["- No dedicated telemetry profile matched this alert. The report is trigger-led and may lack correlated evidence."]
    return [f"- {_PROFILE_LABELS.get(item.get('profile_id'), item.get('profile_id') or 'unknown profile')}: `{item.get('status') or 'unknown'}`." for item in profiles[:2]]


def _model_metadata_lines(case: InvestigationCase) -> list[str]:
    execution = case.correlations.get("model_execution", {}) if isinstance(case.correlations, Mapping) else {}
    if not isinstance(execution, Mapping):
        return ["- LLM model: `not recorded`"]
    lines = []
    for stage, label in (("assessment", "Assessment model"), ("qa", "QA model")):
        item = execution.get(stage)
        if not isinstance(item, Mapping) or not item.get("invoked"):
            continue
        provider, model = item.get("provider") or "unknown", item.get("model") or "unknown"
        lines.append(f"- {label}: `{provider}/{model}` (called)")
    return lines


def _card_line(card: Mapping[str, Any]) -> str:
    observed = card.get("observed", {}) if isinstance(card.get("observed"), Mapping) else {}
    kind = str(card.get("kind", "activity"))
    seed_image = observed.get("image")
    label = {"seed_process": "Process observed" if seed_image not in (None, "", "unknown") else "Alerting event", "direct_parent": "Parent process", "process_access": "Process access"}.get(kind, kind.capitalize())
    evidence = ", ".join(str(item) for item in card.get("evidence_ids", [])[:4]) or "none"
    return f"- `{card.get('card_id', 'R??')}` — {label}: {'; '.join(_readable_fields(kind, observed))}. Evidence: {evidence}."


def _judgment_section_lines(items: Any, fallback: str) -> list[str]:
    if not isinstance(items, list) or not items:
        return [f"- {fallback}"]
    lines = []
    for item in items[:2]:
        if not isinstance(item, Mapping):
            continue
        text = item.get("text")
        refs = item.get("refs")
        if isinstance(text, str) and isinstance(refs, list):
            lines.append(f"- {text} Evidence: {', '.join(str(ref) for ref in refs)}.")
    return lines or [f"- {fallback}"]


def _readable_fields(kind: str, observed: Mapping[str, Any]) -> list[str]:
    keys = {
        "seed_process": ("host", "image", "command_line", "parent_image", "user"),
        "direct_parent": ("image",),
        "process_access": ("source_process", "target_process", "granted_access", "source_relationship", "target_relationship", "occurrences"),
    }.get(kind, ("process", "affected_object", "affected_objects", "event_id", "event_ids", "process_relationship", "process_creation_context", "occurrences"))
    values = []
    for key in keys:
        value = observed.get(key)
        if value in (None, "", [], "unknown", "unresolved"):
            continue
        values.append(f"{key.replace('_', ' ')}={_compact_value(value, 240)}")
    return values or ["no readable event fields were retained"]


def _actions(assessment: VerifiedAssessment, confidence: float) -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    confidence_view = type("Confidence", (), {"score": confidence})()
    for item in advise(assessment, confidence_view):
        result.append((item.action, item.reason, item.risk))
    if assessment.status == "accepted":
        for item in assessment.recommended_actions:
            action = str(item.get("action"))
            if action and action not in {existing[0] for existing in result}:
                result.append((action, str(item.get("reason", "No reason recorded.")), str(item.get("risk", "No risk recorded."))))
    return result


def _targeted_collection_steps(limitations: list[str]) -> list[str]:
    """Translate recorded coverage gaps into bounded, analyst-readable asks."""
    text = " ".join(limitations).lower()
    steps: list[str] = []
    if "parentprocessguid" in text or "parent process" in text:
        steps.append("- Collect the seed process-create record and its direct parent context if archive retention or endpoint telemetry permits.")
    if "process references" in text or "process-creation record" in text:
        steps.append("- Collect missing Sysmon Event ID 1 records for the cited process-access source or target before interpreting access values.")
    if "change record" in text or "authorization" in text:
        steps.append("- Confirm whether the named host, user, time, and activity were authorized through the available operational channel.")
    return steps[:2]


def _collection_limitations(case: InvestigationCase) -> list[str]:
    """Surface only a material source-coverage limitation, never tool noise."""
    if any(item.get("source") == "alerts_fallback" for item in case.tool_history):
        return ["Related context came from the alerts index only; ordinary non-alert endpoint activity may be unavailable."]
    return []


def _coverage_lines(case: InvestigationCase) -> list[str]:
    telemetry = [item for item in case.tool_history if item.get("source") in {"telemetry", "alerts_fallback"}]
    if not telemetry:
        return ["- No follow-on telemetry query was recorded."]
    lines = [f"- `{item['tool']}`: {item.get('count', 0)} record(s) from `{item.get('source')}` / `{item.get('index') or 'unknown index'}`." for item in telemetry[:MAX_COVERAGE_ROWS]]
    if any(item.get("source") == "alerts_fallback" for item in telemetry):
        lines.append("- Limitation: alerts-only context can omit ordinary, non-alert endpoint activity.")
    return lines


def _claim_summary(claim: Any) -> str:
    labels = {
        "encoded_powershell": "Encoded PowerShell execution was observed",
        "process_parent": "A direct parent-to-child process relationship was observed",
        "authentication_window": "Authentication activity was observed",
        "network_connection": "A process-linked network connection was observed",
    }
    return labels.get(getattr(claim, "claim_type", ""), "A verified claim was recorded")


def _compact_value(value: Any, limit: int) -> str:
    if isinstance(value, Mapping):
        rendered = ", ".join(f"{key}={item}" for key, item in value.items())
    elif isinstance(value, list):
        rendered = ", ".join(str(item) for item in value)
    else:
        rendered = str(value or "not recorded")
    return rendered if len(rendered) <= limit else rendered[:limit] + "…[truncated]"


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
