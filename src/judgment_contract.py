"""Versioned, evidence-cited analyst-judgment contract for any Wazuh alert."""
from __future__ import annotations

import json
from typing import Any, Mapping

try:
    from .assessment_dossier import build_dossier
    from .case_models import InvestigationCase
    from .reasoning_narrative import _SPECIFIC_VALUE
except ImportError:
    from assessment_dossier import build_dossier
    from case_models import InvestigationCase
    from reasoning_narrative import _SPECIFIC_VALUE


VERDICTS = {"likely_benign", "inconclusive", "suspicious_requires_review", "likely_malicious"}
SECTION_NAMES = (
    "what_happened", "alert_claim_assessment", "reassuring_factors",
    "concern_factors", "competing_hypotheses",
)
_REQUIRED_SECTIONS = {"what_happened", "alert_claim_assessment"}
_EXAMPLE_NARRATIVES = {
    "the cited observation records activity; it does not establish intent or outcome.",
    "the wazuh alert is a detection trigger; the cited observation is the available evidence for review.",
}


def is_judgment_payload(payload: Mapping[str, Any]) -> bool:
    return "what_happened" in payload or "alert_claim_assessment" in payload


def resolve_judgment(case: InvestigationCase, payload: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate V2 assessor output and resolve all selectors to report data."""
    expected = {
        "verdict", "confidence", "claim_verification_id", "what_happened",
        "alert_claim_assessment", "reassuring_factors", "concern_factors",
        "competing_hypotheses", "evidence_gap_ids", "next_check_id", "action_ids",
    }
    if set(payload) != expected:
        raise ValueError("judgment output has an invalid schema")
    verdict, confidence = payload["verdict"], payload["confidence"]
    if verdict not in VERDICTS:
        raise ValueError("judgment output has an invalid verdict")
    if not isinstance(confidence, int) or isinstance(confidence, bool) or not 0 <= confidence <= 100:
        raise ValueError("judgment confidence must be an integer from 0 to 100")

    dossier = build_dossier(case)
    claim = dossier["alert_claim"]
    if payload["claim_verification_id"] != claim["status_id"]:
        raise ValueError("claim_verification_id contains an unknown option")
    next_checks = {item["id"]: item["text"] for item in dossier["next_check_options"]}
    if payload["next_check_id"] not in next_checks:
        raise ValueError("next_check_id contains an unknown option")
    unknowns = {item["id"]: item["text"] for item in dossier["unknown_options"]}
    _known_ids(payload["evidence_gap_ids"], unknowns, "evidence_gap_ids")
    actions = {item["id"]: item["action"] for item in dossier["action_options"]}
    _known_ids(payload["action_ids"], actions, "action_ids")

    sources = _narrative_sources(dossier)
    sections: dict[str, list[dict[str, Any]]] = {}
    for name in SECTION_NAMES:
        sections[name] = _section(name, payload[name], sources)
    if any(not sections[name] for name in _REQUIRED_SECTIONS):
        raise ValueError("judgment output omits a required narrative section")
    _validate_judgment(verdict, confidence, sections, claim["status"], payload["evidence_gap_ids"])

    legacy = {
        "verdict": verdict,
        "llm_confidence": confidence / 100,
        "claims": [],
        "benign_alternatives": [],
        "unknowns": [unknowns[item] for item in payload["evidence_gap_ids"]],
        "recommended_actions": [_action(actions[item], case) for item in payload["action_ids"]],
    }
    guidance = {
        "contract_version": "judgment_v2",
        "claim_verification": claim,
        "sections": sections,
        "next_check": next_checks[payload["next_check_id"]],
        "confidence_rationale": _confidence_rationale(confidence, claim["status"], payload["evidence_gap_ids"]),
    }
    return legacy, guidance


def _section(name: str, value: Any, sources: Mapping[str, str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 2:
        raise ValueError(f"{name} must contain zero to two cited items")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"refs", "text"}:
            raise ValueError(f"{name} item has an invalid schema")
        refs, text = item["refs"], item["text"]
        if not isinstance(refs, list) or not 1 <= len(refs) <= 4 or not all(isinstance(ref, str) for ref in refs) or len(set(refs)) != len(refs) or not set(refs).issubset(sources):
            raise ValueError(f"{name} item cites unknown evidence")
        if not isinstance(text, str) or not 20 <= len(text.strip()) <= 600:
            raise ValueError(f"{name} text must be 20 to 600 characters")
        if text.strip().casefold() in _EXAMPLE_NARRATIVES:
            raise ValueError(f"{name} copies the prompt example instead of narrating cited evidence")
        cited = " ".join(sources[ref].lower() for ref in refs)
        for observed in _SPECIFIC_VALUE.findall(text):
            if observed.lower() not in cited:
                raise ValueError(f"{name} introduces an uncited specific value")
        result.append({"refs": refs, "text": text.strip()})
    return result


def _narrative_sources(dossier: Mapping[str, Any]) -> dict[str, str]:
    sources: dict[str, str] = {}
    for card in dossier.get("activity_cards", []):
        if isinstance(card, Mapping) and isinstance(card.get("card_id"), str):
            sources[card["card_id"]] = json.dumps(card, default=str)
    for item in dossier.get("derived_observations", []):
        if isinstance(item, Mapping) and isinstance(item.get("id"), str) and isinstance(item.get("text"), str):
            sources[item["id"]] = item["text"]
    return sources


def _validate_judgment(verdict: str, confidence: int, sections: Mapping[str, list[dict[str, Any]]], claim_status: str, gaps: list[str]) -> None:
    if verdict == "likely_benign" and not sections["reassuring_factors"]:
        raise ValueError("likely_benign requires a cited reassuring factor")
    if verdict == "likely_malicious":
        concern_refs = {ref for item in sections["concern_factors"] for ref in item["refs"]}
        if len(concern_refs) < 2:
            raise ValueError("likely_malicious requires two independent cited concern references")
        if confidence < 60:
            raise ValueError("likely_malicious requires confidence of at least 60")
    cap = 100
    if claim_status == "not_independently_verified":
        cap = min(cap, 65)
    if gaps:
        cap = min(cap, 65)
    if verdict == "likely_benign":
        cap = min(cap, 70)
    if confidence > cap:
        raise ValueError(f"confidence {confidence} exceeds evidence cap of {cap}")


def _known_ids(value: Any, options: Mapping[str, Any], name: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value) or not set(value).issubset(options):
        raise ValueError(f"{name} contains an unknown option")


def _action(action: str, case: InvestigationCase) -> dict[str, Any]:
    evidence_ids = [case.evidence[0].evidence_id] if case.evidence else []
    templates = {
        "preserve_evidence": ("Preserve the cited telemetry and relevant context before retention expires.", "Collection may consume analyst time and storage."),
        "validate_change": ("Validate whether the observed activity was authorized.", "A delayed validation may postpone a response decision."),
    }
    reason, risk = templates[action]
    return {"action": action, "reason": reason, "risk": risk, "evidence_ids": evidence_ids}


def _confidence_rationale(confidence: int, claim_status: str, gaps: list[str]) -> str:
    parts = [f"Model confidence: {confidence}%."]
    if claim_status == "not_independently_verified":
        parts.append("Confidence is capped because the Wazuh detection claim was not independently verified.")
    if gaps:
        parts.append("Confidence is capped because material evidence gaps were selected.")
    return " ".join(parts)
