"""Objective L3-readiness gate for evidence-grounded analyst reports."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

try:
    from .assessment import VerifiedAssessment
    from .assessment_dossier import build_dossier
    from .case_models import InvestigationCase
except ImportError:
    from assessment import VerifiedAssessment
    from assessment_dossier import build_dossier
    from case_models import InvestigationCase


@dataclass(frozen=True)
class ReportQuality:
    score: int
    ready_for_l3: bool
    checks: dict[str, bool]
    gaps: list[str]


def assess_l3_readiness(case: InvestigationCase, assessment: VerifiedAssessment) -> ReportQuality:
    """Score report mechanics, not whether an incident is malicious.

    Nine points is the release bar. A score is deliberately withheld from the
    report itself; it is a developer/benchmark quality signal.
    """
    dossier = build_dossier(case)
    trigger = dossier.get("trigger", {})
    cards = dossier.get("activity_cards", [])
    review = assessment.quality_review or {}
    narrative = assessment.narrative or []
    guidance = assessment.investigation_guidance or {}
    sections = guidance.get("sections", {}) if isinstance(guidance, Mapping) else {}
    activity_ids = {card["card_id"] for card in cards if card.get("kind") not in {"seed_process", "direct_parent"}}
    cited = {card_id for item in narrative for card_id in item.get("card_ids", [])}
    section_refs = {
        ref for items in sections.values() if isinstance(items, list)
        for item in items if isinstance(item, Mapping)
        for ref in item.get("refs", []) if isinstance(ref, str)
    }
    has_v2_reasoning = bool(section_refs)
    checks = {
        "wazuh_trigger_preserved": bool(trigger.get("title") and trigger.get("rule_id") is not None),
        "evidence_is_reduced": bool(cards) and len(cards) <= 12 and all(card.get("evidence_ids") for card in cards),
        "assessment_verified": assessment.status == "accepted",
        # A sparse but valid alert can legitimately have no correlated activity
        # card. In that case cited seed reasoning is acceptable; otherwise the
        # narrative must engage at least one activity card.
        "reasoning_cites_activity": (bool(narrative) and (not activity_ids or bool(cited & activity_ids))) or has_v2_reasoning,
        "uncertainty_explicit": bool(assessment.unknowns),
        "proportionate_next_step": bool(assessment.recommended_actions) or bool(guidance.get("next_check") if isinstance(guidance, Mapping) else None),
        "critic_accepted": review.get("status") == "accepted" and review.get("decision") == "accept",
        "no_rejected_claims": not assessment.rejected_claims,
        "correlation_auditable": all(item.get("evidence_ids") for item in cards),
        "scope_recorded": bool(case.correlations.get("telemetry_profiles")),
    }
    assessment_gap = (
        "QA requested revision; the otherwise verified assessor output is withheld."
        if assessment.status == "qa_revision_required"
        else "LLM assessment was not accepted."
    )
    descriptions = {
        "wazuh_trigger_preserved": "Wazuh alert title/rule ID is missing.",
        "evidence_is_reduced": "Evidence packet is absent, oversized, or lacks source IDs.",
        "assessment_verified": assessment_gap,
        "reasoning_cites_activity": "No accepted reasoning cites correlated activity.",
        "uncertainty_explicit": "Material uncertainty is not stated.",
        "proportionate_next_step": "No analyst next step is provided.",
        "critic_accepted": "QA critic did not accept the assessment.",
        "no_rejected_claims": "A claim was rejected by deterministic verification.",
        "correlation_auditable": "Reduced cards cannot be traced to evidence IDs.",
        "scope_recorded": "Telemetry profile/scope was not recorded.",
    }
    gaps = [descriptions[name] for name, passed in checks.items() if not passed]
    score = sum(checks.values())
    # A report can be well-formed but cannot be an L3 investigation of a
    # Wazuh alert if there was no Wazuh alert trigger in the first place.
    return ReportQuality(
        score=score,
        ready_for_l3=(
            score >= 9
            and checks["wazuh_trigger_preserved"]
            and checks["critic_accepted"]
        ),
        checks=checks,
        gaps=gaps,
    )
