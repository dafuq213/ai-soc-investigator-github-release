"""Single, generic LLM assessment contract for an evidence packet.

This module does not determine a verdict.  It constrains a model to a bounded
packet and rejects output that lacks the required JSON shape or evidence
citations.  The contract works for any normalized Wazuh alert rather than an
individual detection rule or Sysmon event ID.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html import unescape
from typing import Any, Mapping


VERDICTS = {"likely_benign", "inconclusive", "suspicious_requires_review", "likely_malicious"}
CLAIM_STATUSES = {"supported", "partially_supported", "not_supported", "not_assessable"}
RECOMMENDATION_CATEGORIES = {"investigate", "validate_context", "preserve_evidence", "escalate", "consider_response"}
RECOMMENDATION_PRIORITIES = {"low", "medium", "high"}
RESPONSE_ACTION_TERMS = re.compile(r"^\s*(?:consider\s+)?(?:isolat(?:e|ing)|quarantin(?:e|ing)|block(?:ing)?|disabl(?:e|ing)|terminat(?:e|ing)|kill(?:ing)?|contain(?:ing|ment)?|delet(?:e|ing)|remov(?:e|ing)|reset(?:ting)?)\b", re.IGNORECASE)
APPROVAL_TERMS = re.compile(r"\b(?:human|analyst)\s+approval\b", re.IGNORECASE)
CONCRETE_IDENTIFIER = re.compile(r"(?i)\b(?:[a-z0-9_.-]+\.exe|(?:\d{1,3}\.){3}\d{1,3}|[a-f0-9]{32,64})\b")
WINDOWS_PATH_IDENTIFIER = re.compile(r"(?i)(?<![A-Za-z0-9_])([A-Z]:\\[^\s\"'<>|]+)")
REGISTRY_IDENTIFIER = re.compile(r"(?i)\b((?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s\"'<>|]+)")
HYPOTHESIS_TYPES = {"possible_legitimate_context", "possible_concern"}
# Hypotheses are allowed to use ordinary uncertainty language.  This is
# intentionally semantic rather than a three-phrase style whitelist: model
# wording such as "may legitimately" is bounded even when it does not use the
# prompt's examples verbatim.
HYPOTHESIS_BOUNDING_TERMS = re.compile(
    r"\b(?:"
    r"may|might|could|possibly|potentially|possible|plausible|appears?|suggests?"
    r"|consistent\s+with|cannot\s+(?:determine|establish|confirm)"
    r"|one\s+(?:possible|plausible)\s+explanation"
    r")\b",
    re.IGNORECASE,
)
NARRATIVE_SECTIONS = ("what_happened",)
OPERATIONAL_CONTEXT_TERMS = re.compile(r"\b(?:known|typical|atypical|official|built-in|custom|controlled|expected|approved|authorized|user-installed|bundled|documented|test|testing|fixture|lab|automated|automation)\b", re.IGNORECASE)
OPERATIONAL_CONTEXT_PHRASES = re.compile(r"\b(?:scheduled\s+(?:windows\s+)?(?:background\s+)?(?:maintenance\s+)?task|maintenance\s+task|background\s+maintenance)\b", re.IGNORECASE)
UNVERIFIED_SOFTWARE_OWNERSHIP = re.compile(r"\b(?:own\s+(?:registry\s+)?key|verified|unmodified|installed\s+software)\b", re.IGNORECASE)
# These phrases claim a completed state change. A process command line only
# records requested intent, so at least one cited record must also contain a
# normalized result field before such wording can enter the report.
CONFIRMED_OUTCOME_ASSERTION = re.compile(
    r"\b(?:"
    r"actual\s+(?:value|file|key|entry)\s+(?:was\s+)?(?:written|added|created|deleted|removed|modified|set)"
    r"|(?:registry\s+)?(?:run[- ]?key|value|file|entry)\s+(?:addition|creation|deletion|removal|modification|write)\s+is\s+(?:observed|confirmed)"
    r"|(?:file|key|value|entry)\s+(?:was|were)\s+(?:created|deleted|removed|modified|written|set|added)"
    r")\b",
    re.IGNORECASE,
)
OUTCOME_RESULT_FIELDS = {"registry_key", "registry_value", "file_path", "event_type", "details"}
WEAK_CORRELATION_RELATIONSHIPS = {"same_hash"}
CONTEXT_ONLY_RELATIONSHIPS = {"parent_process_origin", "target_process_origin"}
TEMPORAL_CORRELATION_THRESHOLD_SECONDS = 10 * 60
MAX_MODEL_EVIDENCE_ITEMS = 8
MAX_CITATIONS_PER_ITEM = MAX_MODEL_EVIDENCE_ITEMS


def generic_assessment_prompt(packet: Mapping[str, Any]) -> str:
    """Create one self-contained strict-JSON request from the generic packet."""
    # The model needs readable facts and citation IDs, not document IDs,
    # duplicate host values, or every source reference. Full provenance stays
    # in the persisted evidence packet and analyst report.
    packet_json = json.dumps(_assessment_view(packet), separators=(",", ":"), default=str)
    return f"""You are a SOC investigator. Assess only the supplied evidence.
Return exactly one JSON object: no Markdown, commentary, or extra keys.

Schema:
{{"verdict":"likely_benign|inconclusive|suspicious_requires_review|likely_malicious","confidence":0,"what_happened":[{{"evidence_ids":["E01"],"text":"..."}}],"alert_claim_assessment":{{"status":"supported|partially_supported|not_supported|not_assessable","evidence_ids":["E01"],"text":"..."}},"hypotheses":[{{"type":"possible_legitimate_context|possible_concern","evidence_ids":["E01"],"text":"..."}}],"unknowns":["..."],"recommended_actions":[{{"category":"investigate|validate_context|preserve_evidence|escalate|consider_response","action":"...","reason":"...","evidence_ids":["E01"],"target":null,"priority":"low|medium|high"}}],"analyst_question":"..."}}

Rules:
1. Cite one to {MAX_CITATIONS_PER_ITEM} distinct supplied E## IDs per cited item. `what_happened` is observation only; do not add intent, outcome, authorization, reputation, MITRE, or intelligence not shown by cited evidence. A command line proves that an operation was requested, not that it succeeded or returned particular data unless cited evidence contains that result.
2. The Wazuh title and any source-provided MITRE metadata are detection context, not proof. In `alert_claim_assessment`, say whether the evidence supports the alert claim. If the underlying activity is observed but a judgment such as suspicious, abnormal, malicious, or anomalous is not independently established, use `partially_supported` rather than `supported`.
3. Hypotheses are optional and bounded: at most one of each type. Clearly express uncertainty with language such as “may”, “might”, “could”, “possibly”, “consistent with”, or “cannot determine”; do not present a hypothesis as confirmed fact. Labels, markers, filenames, users, paths, and product names are observed strings—not proof of testing, benign activity, ownership, authorization, or expected behavior.
4. Respect every `relationship_limit` supplied with evidence. A shared hash proves identity only; related-process identity does not prove causation.
5. State real evidence limits in `unknowns`. `likely_benign` requires a legitimate-context hypothesis, two independent observations, and at least one unknown. `likely_malicious` requires two cited concern observations and confidence ≥70. Otherwise prefer `inconclusive` or `suspicious_requires_review`.
6. Independently write zero to three specific, useful recommendations. Cite the evidence that makes each recommendation relevant. Use `target:null` unless copying one exact host, user, IP, process, file, registry key, or domain value from the supplied evidence. Concrete identifiers such as IP addresses, hashes, and executable names must occur in the evidence. A recommendation may request missing telemetry but must not imply it already exists or that an operation succeeded.
7. `consider_response` is recommendation-only, must explicitly require human or analyst approval, and is allowed only for `likely_malicious` with confidence at least 70. Do not recommend isolate, quarantine, block, disable, terminate, kill, or containment under another category.
8. Use one or two cited `what_happened` items. Keep narrative text concise (20–160 characters), unknowns to four items, action/reason text concise, and use empty optional arrays instead of repetition.

EVIDENCE:
{packet_json}
"""


def _assessment_view(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Produce the smallest complete model input while retaining all citation IDs."""
    alert = _mapping(packet.get("alert"))
    evidence = []
    source_evidence = _select_model_evidence(_list(packet.get("evidence")))
    for item in source_evidence:
        if not isinstance(item, Mapping):
            continue
        fields = _mapping(item.get("fields"))
        compact_fields = {key: _model_value(value) for key, value in fields.items() if key not in {"host", "process_path", "parent_process_path"}}
        # Path fields are duplicated by the readable process identity in most
        # Wazuh mappings. Retain the path only when no process name exists.
        if not compact_fields.get("process_name") and fields.get("process_path"):
            compact_fields["process_path"] = _model_value(fields["process_path"])
        if not compact_fields.get("parent_process_name") and fields.get("parent_process_path"):
            compact_fields["parent_process_path"] = _model_value(fields["parent_process_path"])
        relationship = item.get("relationship")
        relationship_note = (
            "same file hash only; not proof of a shared execution chain or causal relationship"
            if relationship in WEAK_CORRELATION_RELATIONSHIPS else
            "related-process identity context only; not proof this activity caused the seed event"
            if relationship in CONTEXT_ONLY_RELATIONSHIPS else None
        )
        evidence.append({key: item.get(key) for key in ("id", "relationship", "timestamp_utc", "summary") if item.get(key) not in (None, "")} | {"fields": compact_fields, **({"relationship_limit": relationship_note} if relationship_note else {}), **({"occurrence_count": item["occurrence_count"]} if item.get("occurrence_count") else {})})
    return {
        "alert": {key: alert.get(key) for key in ("alert_id", "timestamp_utc", "title", "rule_id", "severity", "source") if alert.get(key) not in (None, "", {})},
        "evidence": evidence,
        "model_input_limit": (
            f"The model received {len(evidence)} of {len(_list(packet.get('evidence')))} bounded evidence records; "
            "the full source-traceable packet remains available to the report."
            if len(evidence) < len(_list(packet.get("evidence"))) else None
        ),
        "collection_limitations": _list(_mapping(packet.get("collection")).get("limitations")),
    }


def _select_model_evidence(items: list[Any]) -> list[Mapping[str, Any]]:
    """Keep the seed and a diverse bounded set for model cost/readability.

    The evidence packet itself is not truncated. Only model input is capped,
    with one item per relationship preferred before repeated relationships.
    """
    records = [item for item in items if isinstance(item, Mapping)]
    if len(records) <= MAX_MODEL_EVIDENCE_ITEMS:
        return records
    selected: list[Mapping[str, Any]] = []
    seed = next((item for item in records if item.get("relationship") == "seed_alert"), records[0])
    selected.append(seed)
    seen = {str(seed.get("relationship"))}
    for item in records:
        relationship = str(item.get("relationship"))
        if item is seed or relationship in seen:
            continue
        selected.append(item)
        seen.add(relationship)
        if len(selected) == MAX_MODEL_EVIDENCE_ITEMS:
            return selected
    for item in records:
        if item not in selected:
            selected.append(item)
            if len(selected) == MAX_MODEL_EVIDENCE_ITEMS:
                break
    return selected


def _model_value(value: Any) -> Any:
    """Remove retained transport escaping from model-visible strings only."""
    if not isinstance(value, str):
        return value
    text = unescape(value)
    retained_escapes = '\\"' in text or bool(re.match(r"^[A-Za-z]:\\\\", text)) or bool(re.match(r"^[^\\]+\\\\[^\\]+$", text))
    return text.replace('\\"', '"').replace("\\\\", "\\") if retained_escapes else text


def parse_generic_assessment(output: str | Mapping[str, Any], packet: Mapping[str, Any]) -> dict[str, Any]:
    """Parse and deterministically validate an assessor response."""
    raw = _parse_json(output)
    expected = {"verdict", "confidence", "what_happened", "alert_claim_assessment", "hypotheses", "unknowns", "recommended_actions", "analyst_question"}
    missing = expected - set(raw)
    if missing:
        raise ValueError("assessment output has an invalid schema")
    flags: list[dict[str, Any]] = []
    extra = sorted(set(raw) - expected)
    if extra:
        flags.append(_flag("extra_fields_removed", f"Ignored non-contract fields: {', '.join(extra)}."))
    raw = {key: raw[key] for key in expected}
    if raw["verdict"] not in VERDICTS:
        raise ValueError("assessment verdict is invalid")
    confidence = _normalize_confidence(raw["confidence"])
    if confidence is None:
        raise ValueError("assessment confidence must be an integer from 0 to 100")
    if confidence != raw["confidence"] or type(confidence) is not type(raw["confidence"]):
        flags.append(_flag("confidence_normalized", "Normalized an integer-like confidence value."))
    raw["confidence"] = confidence
    evidence_ids = {item.get("id") for item in _list(packet.get("evidence")) if isinstance(item, Mapping) and isinstance(item.get("id"), str)}
    sections: dict[str, list[dict[str, Any]]] = {}
    section_validation: dict[str, str] = {}
    for name in NARRATIVE_SECTIONS:
        sections[name], section_flags = _recover_narratives(raw[name], evidence_ids, name, packet)
        flags.extend(section_flags)
        section_validation[name] = "accepted_with_flags" if section_flags else "accepted"
    if not sections["what_happened"]:
        raise ValueError("what_happened requires at least one cited item")
    claim, claim_flags = _recover_claim(raw["alert_claim_assessment"], evidence_ids, packet)
    flags.extend(claim_flags)
    section_validation["alert_claim_assessment"] = "accepted_with_flags" if claim_flags else "accepted"
    hypotheses, hypothesis_flags = _hypotheses(raw["hypotheses"], evidence_ids)
    flags.extend(hypothesis_flags)
    flags.extend(_quality_flags(hypotheses, packet))
    section_validation["hypotheses"] = "accepted_with_flags" if hypothesis_flags else "accepted"
    unknowns, unknown_flags = _recover_unknowns(raw["unknowns"])
    flags.extend(unknown_flags)
    section_validation["unknowns"] = "accepted_with_flags" if unknown_flags else "accepted"
    raw["unknowns"] = unknowns
    verdict, confidence, verdict_flags = _recover_verdict(raw, hypotheses, packet, flags)
    flags.extend(verdict_flags)
    raw["verdict"], raw["confidence"] = verdict, confidence
    recommendations, recommendation_flags = _recover_recommendations(raw["recommended_actions"], evidence_ids, packet, verdict, confidence)
    flags.extend(recommendation_flags)
    section_validation["recommended_actions"] = "accepted_with_flags" if recommendation_flags else "accepted"
    analyst_question = raw["analyst_question"] if _short_text(raw["analyst_question"], 240, allow_empty=True) else ""
    if analyst_question != raw["analyst_question"]:
        flags.append(_flag("analyst_question_removed", "Removed an invalid optional analyst question."))
        section_validation["analyst_question"] = "accepted_with_flags"
    else:
        section_validation["analyst_question"] = "accepted"
    validated = {**raw, "analyst_question": analyst_question, "recommended_actions": recommendations}
    return {**validated, **sections, "alert_claim_assessment": claim, "hypotheses": hypotheses, "quality_flags": flags,
            "section_validation": section_validation,
            "assessment_status": "accepted_with_flags" if flags else "accepted"}


def _flag(code: str, message: str, evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return {"code": code, "evidence_ids": evidence_ids or [], "message": message}


def _normalize_confidence(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        result = value
    elif isinstance(value, float) and value.is_integer():
        result = int(value)
    elif isinstance(value, str) and re.fullmatch(r"\s*\d{1,3}\s*", value):
        result = int(value)
    else:
        return None
    return result if 0 <= result <= 100 else None


def _recover_unknowns(value: Any) -> tuple[list[str], list[dict[str, Any]]]:
    if not isinstance(value, list):
        return [], [_flag("unknowns_removed_invalid", "Removed an invalid optional unknowns section.")]
    valid = [item.strip() for item in value if _short_text(item, 300)]
    flags = []
    if len(valid) != len(value):
        flags.append(_flag("unknowns_removed_invalid", "Removed invalid optional unknown items."))
    if len(valid) > 4:
        valid = valid[:4]
        flags.append(_flag("unknowns_truncated", "Retained the first four valid unknowns."))
    return valid, flags


def _recover_verdict(raw: Mapping[str, Any], hypotheses: list[dict[str, Any]], packet: Mapping[str, Any], flags: list[dict[str, Any]]) -> tuple[str, int, list[dict[str, Any]]]:
    verdict, confidence = str(raw["verdict"]), int(raw["confidence"])
    try:
        _validate_verdict({**raw, "verdict": verdict, "confidence": confidence}, hypotheses, packet, flags)
        return verdict, confidence, []
    except ValueError as exc:
        if verdict == "likely_benign":
            return "inconclusive", min(confidence, 65), [_flag("verdict_downgraded", f"Downgraded unsupported likely_benign verdict: {exc}")]
        if verdict == "likely_malicious":
            return "suspicious_requires_review", min(confidence, 69), [_flag("verdict_downgraded", f"Downgraded unsupported likely_malicious verdict: {exc}")]
        raise


def _recover_recommendations(value: Any, allowed: set[str], packet: Mapping[str, Any], verdict: str, confidence: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(value, list):
        return [], [_flag("recommendations_removed_invalid", "Removed an invalid optional recommendations section.")]
    result: list[dict[str, Any]] = []
    flags: list[dict[str, Any]] = []
    for index, item in enumerate(value[:3]):
        try:
            result.extend(_recommendations([item], allowed, packet, verdict, confidence))
        except ValueError as exc:
            flags.append(_flag("recommendation_removed_invalid", f"Removed recommendation {index + 1}: {exc}"))
    if len(value) > 3:
        flags.append(_flag("recommendations_truncated", "Retained the first three recommendation candidates."))
    return result, flags


def _recommendations(value: Any, allowed: set[str], packet: Mapping[str, Any], verdict: str, confidence: int) -> list[dict[str, Any]]:
    """Validate model-written advice without prescribing its content."""
    if not isinstance(value, list) or len(value) > 3:
        raise ValueError("recommended_actions must contain zero to three items")
    observed_values = [_model_value(item) for item in _leaf_strings(_mapping(packet.get("observed_entities")))]
    for evidence in _list(packet.get("evidence")):
        if isinstance(evidence, Mapping):
            observed_values.extend(_model_value(item) for item in _leaf_strings(_mapping(evidence.get("fields"))))
    observed_targets = _observed_target_candidates(observed_values)
    result = []
    for item in value:
        required = {"category", "action", "reason", "evidence_ids", "target", "priority"}
        if not isinstance(item, Mapping) or set(item) != required:
            raise ValueError("recommended action has an invalid schema")
        category = item["category"]
        if category not in RECOMMENDATION_CATEGORIES or item["priority"] not in RECOMMENDATION_PRIORITIES:
            raise ValueError("recommended action category or priority is invalid")
        if not _short_text(item["action"], 180) or not _short_text(item["reason"], 220):
            raise ValueError("recommended action and reason must be concise strings")
        refs = item["evidence_ids"]
        if not isinstance(refs, list) or not refs or len(refs) > MAX_CITATIONS_PER_ITEM or len(refs) != len(set(refs)) or not set(refs).issubset(allowed):
            raise ValueError("recommended action requires valid distinct evidence citations")
        target = item["target"]
        resolved_target = None
        if target is not None:
            if not isinstance(target, str) or not target.strip() or len(target.strip()) > 300:
                raise ValueError("recommended action target must exactly match an observed evidence value or concrete identifier")
            normalized_target = _model_value(target.strip())
            resolved_target = next((candidate for candidate in observed_targets if candidate.casefold() == normalized_target.casefold()), None)
            if resolved_target is None:
                raise ValueError("recommended action target must exactly match an observed evidence value or concrete identifier")
        observed_text = "\n".join(str(item) for item in observed_values).casefold()
        invented = sorted({match.group(0) for match in CONCRETE_IDENTIFIER.finditer(item["action"] + " " + item["reason"]) if match.group(0).casefold() not in observed_text})
        if invented:
            raise ValueError("recommended action contains a concrete identifier absent from evidence: " + ", ".join(invented))
        response_wording = RESPONSE_ACTION_TERMS.search(item["action"])
        if response_wording and category != "consider_response":
            raise ValueError("response action wording requires consider_response category")
        if category == "consider_response":
            if verdict != "likely_malicious" or confidence < 70:
                raise ValueError("consider_response requires a likely_malicious verdict with confidence of at least 70")
            if not APPROVAL_TERMS.search(item["action"] + " " + item["reason"]):
                raise ValueError("consider_response must explicitly require human or analyst approval")
            if target is None:
                raise ValueError("consider_response requires an exact observed target")
        result.append({**item, "action": item["action"].strip(), "reason": item["reason"].strip(), "target": resolved_target})
    return result


def _observed_target_candidates(values: list[Any]) -> set[str]:
    """Return full observed values plus concrete identifiers embedded within them.

    A command line is an observed field but is rarely a useful action target as
    a whole.  File paths, registry paths, executable names, IP addresses, and
    hashes copied from that field remain evidence-backed targets.  Arbitrary
    prose fragments are deliberately not accepted.
    """
    candidates = {str(value) for value in values if isinstance(value, str) and value}
    for value in tuple(candidates):
        candidates.update(match.group(0) for match in CONCRETE_IDENTIFIER.finditer(value))
        candidates.update(match.group(1).rstrip("),;:") for match in WINDOWS_PATH_IDENTIFIER.finditer(value))
        candidates.update(match.group(1).rstrip("),;:") for match in REGISTRY_IDENTIFIER.finditer(value))
    return candidates


def _validate_observed_outcomes(items: list[Mapping[str, Any]], packet: Mapping[str, Any]) -> None:
    """Reject completed-operation claims supported only by command intent."""
    evidence_by_id = {
        item.get("id"): item for item in _list(packet.get("evidence"))
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    for item in items:
        text = str(item.get("text", ""))
        if not CONFIRMED_OUTCOME_ASSERTION.search(text):
            continue
        # Explicitly bounded statements remain valid observations of a limit.
        if re.search(r"\b(?:not|isn't|is not|wasn't|was not)\b.{0,50}\b(?:observed|confirmed|verified|established)\b", text, re.IGNORECASE):
            continue
        cited = [evidence_by_id.get(ref, {}) for ref in _list(item.get("evidence_ids"))]
        has_result = any(
            any(fields.get(key) not in (None, "") for key in OUTCOME_RESULT_FIELDS)
            for evidence in cited
            for fields in [_mapping(evidence.get("fields"))]
        )
        if not has_result:
            raise ValueError("assessment asserts a completed operation from command-line intent without cited outcome telemetry")


def _validate_verdict(raw: Mapping[str, Any], hypotheses: list[dict[str, Any]], packet: Mapping[str, Any], flags: list[dict[str, Any]]) -> None:
    concern_ids = {ref for item in hypotheses if item["type"] == "possible_concern" for ref in item["evidence_ids"]}
    legitimate_ids = {ref for item in hypotheses if item["type"] == "possible_legitimate_context" for ref in item["evidence_ids"]}
    if raw["verdict"] == "likely_benign":
        if raw["confidence"] < 35:
            raise ValueError("likely_benign requires confidence of at least 35")
        if len(_independent_relationships(packet, legitimate_ids)) < 2:
            raise ValueError("likely_benign requires two independent cited observations")
        if not raw["unknowns"]:
            raise ValueError("likely_benign requires at least one evidence limitation")
    if raw["verdict"] == "likely_malicious":
        if len(concern_ids) < 2:
            raise ValueError("likely_malicious requires two cited concern sources")
        if raw["confidence"] < 70:
            raise ValueError("likely_malicious requires confidence of at least 70")
    if flags and raw["verdict"] == "likely_benign" and raw["confidence"] > 65:
        raise ValueError("likely_benign confidence above 65 is not allowed with unverified operational-context flags")


def _hypotheses(value: Any, allowed: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate hypotheses without discarding an otherwise usable assessment.

    Structural and citation failures remain hard failures because they break
    the evidence contract.  A well-formed but assertively worded optional
    hypothesis is quarantined and exposed as a quality flag.  Verdict gates
    still run against the retained hypotheses, so a likely-benign or
    likely-malicious verdict cannot rely on an item that was removed.
    """
    if not isinstance(value, list):
        return [], [_flag("hypotheses_removed_invalid", "Removed an invalid optional hypotheses section.")]
    result: list[dict[str, Any]] = []
    flags: list[dict[str, Any]] = []
    types: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != {"type", "evidence_ids", "text"} or item["type"] not in HYPOTHESIS_TYPES:
            flags.append(_flag("hypothesis_removed_invalid", f"Removed hypothesis {index + 1} because its schema was invalid."))
            continue
        if item["type"] in types:
            flags.append(_flag("hypothesis_removed_duplicate_type", f"Removed duplicate {item['type']} hypothesis."))
            continue
        try:
            narrative = _narratives([{"evidence_ids": item["evidence_ids"], "text": item["text"]}], allowed, "hypothesis")[0]
        except ValueError as exc:
            flags.append(_flag("hypothesis_removed_invalid", f"Removed hypothesis {index + 1}: {exc}"))
            continue
        types.add(item["type"])
        if not HYPOTHESIS_BOUNDING_TERMS.search(narrative["text"]):
            flags.append({
                "code": "hypothesis_removed_unbounded",
                "evidence_ids": narrative["evidence_ids"],
                "message": "An optional hypothesis was omitted because it was written as an assertion rather than a bounded possibility.",
            })
            continue
        result.append({"type": item["type"], **narrative})
    return result, flags


def _recover_narratives(value: Any, allowed: set[str], name: str, packet: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Retain valid factual items and quarantine malformed optional siblings."""
    if not isinstance(value, list):
        return [], [_flag(f"{name}_removed_invalid", f"{name} was not a list.")]
    result: list[dict[str, Any]] = []
    flags: list[dict[str, Any]] = []
    errors: list[ValueError] = []
    for index, item in enumerate(value[:2]):
        try:
            narrative = _narratives([item], allowed, name)[0]
            _validate_observed_outcomes([narrative], packet)
            result.append(narrative)
        except ValueError as exc:
            errors.append(exc)
            flags.append(_flag(f"{name}_item_removed", f"Removed {name} item {index + 1}: {exc}"))
    if len(value) > 2:
        flags.append(_flag(f"{name}_truncated", f"Retained the first two {name} candidates."))
    if not result and errors:
        # Factual grounding is the irreducible core. Do not replace or invent it.
        raise errors[0]
    return result, flags


def _recover_claim(value: Any, allowed: set[str], packet: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        claim = _claim_assessment(value, allowed)
        _validate_observed_outcomes([claim], packet)
        return claim, []
    except ValueError as exc:
        first = sorted(allowed)[0] if allowed else None
        if first is None:
            raise ValueError("alert_claim_assessment is unusable and no evidence is available") from exc
        return {
            "status": "not_assessable",
            "evidence_ids": [first],
            "text": "The alert claim could not be assessed from the validated model output.",
        }, [_flag("alert_claim_assessment_replaced", f"Replaced an invalid claim assessment: {exc}", [first])]


def _quality_flags(hypotheses: list[dict[str, Any]], packet: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flag, rather than discard, bounded operational-context hypotheses.

    The model may suggest an explanation such as a controlled test only when it
    cites packet evidence and labels it as a hypothesis. The report must then
    make clear that authorization/origin was not collected.
    """
    flags: list[dict[str, Any]] = []
    evidence_by_id = {item.get("id"): item for item in _list(packet.get("evidence")) if isinstance(item, Mapping)}
    for item in hypotheses:
        matches = sorted({match.group(0).casefold() for match in OPERATIONAL_CONTEXT_TERMS.finditer(item["text"])} | {match.group(0).casefold() for match in OPERATIONAL_CONTEXT_PHRASES.finditer(item["text"])})
        if matches:
            flags.append({
                "code": "unverified_operational_context",
                "evidence_ids": item["evidence_ids"],
                "message": "This bounded hypothesis uses unverified operational context (" + ", ".join(matches) + "). Authorization and origin were not collected.",
            })
        if UNVERIFIED_SOFTWARE_OWNERSHIP.search(item["text"]):
            flags.append({
                "code": "unverified_software_identity",
                "evidence_ids": item["evidence_ids"],
                "message": "This hypothesis treats a product/path label as verified software identity or ownership. Installation, signer, and provenance were not collected.",
            })
        relationships = {evidence_by_id.get(ref, {}).get("relationship") for ref in item["evidence_ids"]}
        if relationships and relationships.issubset(WEAK_CORRELATION_RELATIONSHIPS):
            flags.append({
                "code": "weak_correlation_basis",
                "evidence_ids": item["evidence_ids"],
                "message": "This hypothesis relies only on same-hash observations. Shared file identity does not establish execution-chain or causal linkage.",
            })
        span = _evidence_time_span_seconds(evidence_by_id, item["evidence_ids"])
        if span is not None and span > TEMPORAL_CORRELATION_THRESHOLD_SECONDS:
            flags.append({
                "code": "weak_temporal_link",
                "evidence_ids": item["evidence_ids"],
                "message": "This hypothesis combines evidence more than ten minutes apart. The packet does not establish a single causal sequence across that time span.",
            })
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for flag in flags:
        identity = (str(flag["code"]), tuple(sorted(str(item) for item in flag["evidence_ids"])))
        if identity not in seen:
            seen.add(identity)
            unique.append(flag)
    return unique


def _evidence_time_span_seconds(evidence_by_id: Mapping[Any, Mapping[str, Any]], evidence_ids: list[str]) -> float | None:
    times = []
    for evidence_id in evidence_ids:
        value = evidence_by_id.get(evidence_id, {}).get("timestamp_utc")
        if not isinstance(value, str):
            continue
        try:
            times.append(datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc))
        except ValueError:
            continue
    return (max(times) - min(times)).total_seconds() if len(times) >= 2 else None


def _independent_relationships(packet: Mapping[str, Any], evidence_ids: set[str]) -> set[str]:
    """Do not treat repeated hashes or duplicates as independent benign support."""
    evidence = {item.get("id"): item for item in _list(packet.get("evidence")) if isinstance(item, Mapping)}
    relationships = set()
    for evidence_id in evidence_ids:
        relationship = evidence.get(evidence_id, {}).get("relationship")
        if isinstance(relationship, str) and relationship not in {"same_hash", "same_process"}:
            relationships.add(relationship)
    return relationships


def _narratives(value: Any, allowed: set[str], name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 2:
        raise ValueError(f"{name} must contain zero to two cited items")
    output = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"evidence_ids", "text"}:
            raise ValueError(f"{name} has an invalid narrative item")
        refs = item["evidence_ids"]
        if not isinstance(refs, list) or not refs:
            raise ValueError(f"{name} requires at least one evidence citation")
        refs = list(dict.fromkeys(refs))
        if len(refs) > MAX_CITATIONS_PER_ITEM:
            raise ValueError(f"{name} exceeds the maximum of {MAX_CITATIONS_PER_ITEM} evidence citations")
        if not set(refs).issubset(allowed):
            raise ValueError(f"{name} cites unknown evidence")
        if not _short_text(item["text"], 500):
            raise ValueError(f"{name} narrative text is invalid")
        if name == "what_happened" and re.search(r"\b(?:consistent with|could indicate|may warrant review|authorized|approved|expected)\b", item["text"], flags=re.IGNORECASE):
            raise ValueError("what_happened must contain observations, not a hypothesis or operational-context conclusion")
        output.append({"evidence_ids": refs, "text": item["text"].strip()})
    return output


def _claim_assessment(value: Any, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"status", "evidence_ids", "text"}:
        raise ValueError("alert_claim_assessment has an invalid schema")
    if value["status"] not in CLAIM_STATUSES:
        raise ValueError("alert_claim_assessment status is invalid")
    items = _narratives([{"evidence_ids": value["evidence_ids"], "text": value["text"]}], allowed, "alert_claim_assessment")
    return {"status": value["status"], **items[0]}


def _parse_json(output: str | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(output, Mapping):
        return dict(output)
    if not isinstance(output, str):
        raise ValueError("assessment output must be JSON")
    value = output.strip()
    match = re.fullmatch(r"```(?:json)?\s*(\{.*\})\s*```", value, flags=re.DOTALL | re.IGNORECASE)
    raw = json.loads(match.group(1) if match else value)
    if not isinstance(raw, Mapping):
        raise ValueError("assessment output must be an object")
    return raw


def _short_text(value: Any, maximum: int, allow_empty: bool = False) -> bool:
    return isinstance(value, str) and len(value.strip()) <= maximum and (allow_empty or len(value.strip()) >= 20)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _leaf_strings(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [item for child in value.values() for item in _leaf_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _leaf_strings(child)]
    return [value] if isinstance(value, str) and value.strip() else []
