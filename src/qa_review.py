"""Independent quality gate for an evidence-verified LLM assessment.

The critic is deliberately narrower than the investigator: it may identify
overstatement, missing uncertainty, context confusion, or unsafe advice.  It
cannot create findings, fetch data, or repair an assessment by inventing text.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, replace
from typing import Any, Callable, Mapping

try:
    from .assessment import VerifiedAssessment
    from .case_models import InvestigationCase
    from .assessment_dossier import build_dossier
except ImportError:
    from assessment import VerifiedAssessment
    from case_models import InvestigationCase
    from assessment_dossier import build_dossier


ISSUE_TYPES = {"overstatement", "missing_uncertainty", "context_confusion", "unsafe_recommendation", "missing_alternative"}

# These sources are deliberately outside the V1 investigation surface.  The
# report can ask an analyst to consult them, but a critic must not demand them
# as a condition for accepting a bounded, evidence-grounded assessment.  If an
# assessor falsely *claims* authorization, the correct critic issue is
# ``overstatement`` against that claim, never ``missing_uncertainty``.
_OUT_OF_SCOPE_CONTEXT_TERMS = (
    "change record", "change ticket", "change management", "expected activity",
    "expected-activity", "approved automation", "authorization context",
)


@dataclass(frozen=True)
class QualityReview:
    status: str
    decision: str
    issues: list[dict[str, Any]]
    required_changes: list[str]
    error: str | None = None
    raw_model_output: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def qa_prompt(case: InvestigationCase, assessment: VerifiedAssessment) -> str:
    """Build a compact critic packet from accepted findings only.

    No raw events, tool history, or contextual evidence content is sent.  The
    critic receives labels and exact verified claim shapes so it cannot turn a
    review into a second unbounded investigation.
    """
    # Use precisely the same reduced, GUID-free activity view as the assessor.
    # A critic receives no broader telemetry than the assessment it reviews.
    dossier = build_dossier(case)
    cards = dossier["activity_cards"]
    # The critic must not be biased by a Wazuh rule description such as
    # "possible injection". It receives the same normalized cards as the
    # assessment stage, mapped back to their original evidence IDs.
    evidence: dict[str, list[dict[str, Any]]] = {}
    for card in cards:
        compact = {"card_id": card["card_id"], "kind": card["kind"], "observed": card["observed"]}
        for evidence_id in card["evidence_ids"]:
            evidence.setdefault(evidence_id, []).append(compact)
    claims = [
        {"ref": f"C{index}", "claim_type": claim.claim_type, "evidence_ids": claim.evidence_ids}
        for index, claim in enumerate(assessment.accepted_claims, start=1)
    ]
    actions = [
        {"ref": f"A{index}", "action": action["action"], "reason": action["reason"],
         "risk": action["risk"], "evidence_ids": action["evidence_ids"]}
        for index, action in enumerate(assessment.recommended_actions, start=1)
    ]
    packet = {
        "verdict": assessment.verdict,
        "confidence": assessment.confidence,
        "claims": claims,
        "benign_alternatives": assessment.benign_alternatives,
        "unknowns": assessment.unknowns,
        "recommendations": actions,
        "reduced_activity_cards": cards,
        "profile_observation": dossier.get("profile_observation"),
        "evidence_catalog": {key: evidence[key] for key in sorted({ref for claim in claims for ref in claim["evidence_ids"]} | {ref for action in actions for ref in action["evidence_ids"]}) if key in evidence},
        "contextual_evidence_ids": sorted(case.contextual_evidence_ids),
    }
    return f"""You are the quality-assurance critic for a defensive SOC investigation.
Return only one JSON object and do not add investigative facts.

You may only flag an accepted claim or response action for: overstatement,
missing_uncertainty, context_confusion, unsafe_recommendation, or
missing_alternative. You may not propose a new verdict, entity, evidence ID,
response action, benign explanation, or finding.

Return exactly:
{{"decision":"accept|revise","issues":[{{"issue_type":"allowed type","target":"C1|A1","reason":"review explanation","evidence_ids":["E001"]}}],"required_changes":["revision instruction"]}}

Rules:
- `target` is restricted to an existing `C#` or `A#` reference. Never use `assessment`, `unknowns`, `narrative`, an `R#` card, or any other label.
- Use only IDs in the REVIEW PACKET.
- Return at most two issues. Keep each `reason` under 180 characters and each `required_changes` item under 140 characters so the complete JSON fits the response budget.
- Contextual evidence is not causal evidence.
- An empty issue list requires decision=accept; any issue requires decision=revise.
- A review is not a source of facts. State concerns, not assertions about unseen activity.
- A selected item in `unknowns` explicitly acknowledges that uncertainty. Do not flag
  `missing_uncertainty` merely because the underlying fact remains unknown.
- Every selected item in `unknowns` is rendered verbatim in the analyst report.
  Therefore, when `unknowns` is non-empty, a `missing_uncertainty` issue is not
  permitted for any of those listed limitations; check the packet before choosing
  `revise`.
- Narrative citation and field-value grounding are validated deterministically
  before this review. Narrative wording is outside this critic's scope. Do not
  infer normal behavior, intent, authorization, or a new alternative explanation
  from process names or access values.
- Do not request change records, expected-activity data, approved-automation
  identity, or authorization context. Those are outside this product's evidence
  collection scope and are rendered as analyst follow-up questions, not QA
  blockers. If a claim asserts authorization without evidence, flag that claim
  as `overstatement` instead.

REVIEW PACKET:
{json.dumps(packet, separators=(",", ":"), default=str)}
"""


class QualityGate:
    def review(self, case: InvestigationCase, assessment: VerifiedAssessment, output: str | Mapping[str, Any]) -> QualityReview:
        if assessment.status != "accepted":
            return QualityReview("skipped", "revise", [], [], "assessment was not accepted")
        try:
            raw = _review_mapping(output)
            review = _parse_review(case, assessment, raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            return QualityReview("rejected", "revise", [], [], f"invalid QA output: {exc}", output if isinstance(output, str) else None)
        return replace(review, raw_model_output=output if isinstance(output, str) else json.dumps(output))


def review_with_model(case: InvestigationCase, assessment: VerifiedAssessment, produce: Callable[[InvestigationCase, VerifiedAssessment], str]) -> QualityReview:
    try:
        output = produce(case, assessment)
    except Exception as exc:
        return QualityReview("unavailable", "revise", [], [], f"QA provider failed: {exc}")
    return QualityGate().review(case, assessment, output)


def apply_quality_gate(assessment: VerifiedAssessment, review: QualityReview) -> VerifiedAssessment:
    """A non-accepting critic blocks model findings from the analyst report."""
    if assessment.status != "accepted" or review.status == "accepted" and review.decision == "accept":
        return replace(assessment, quality_review=review.to_dict())
    return replace(
        assessment, status="qa_revision_required", verdict="inconclusive", confidence=0.0,
        accepted_claims=[], benign_alternatives=[], recommended_actions=[],
        unknowns=["QA review requires revision before this model assessment can be used."],
        narrative=[],
        error=review.error or "QA review found issues requiring revision",
        quality_review=review.to_dict(),
    )


def _review_mapping(output: str | Mapping[str, Any]) -> Mapping[str, Any]:
    """Parse strict JSON, allowing only one otherwise-valid fenced object.

    Some API models wrap a requested JSON response in a Markdown fence.  The
    fence is presentation-only, so accepting it is safe only when it encloses
    the entire response. Extra prose remains a hard failure and the parsed
    object still passes the normal allowlist/schema validation below.
    """
    if not isinstance(output, str):
        return dict(output)
    value = output.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(\{.*\})\s*```", value, flags=re.DOTALL | re.IGNORECASE)
    return json.loads(fenced.group(1) if fenced else value)


def _parse_review(case: InvestigationCase, assessment: VerifiedAssessment, raw: Mapping[str, Any]) -> QualityReview:
    if set(raw) != {"decision", "issues", "required_changes"}:
        raise ValueError("review has an invalid schema")
    decision, issues, changes = raw["decision"], raw["issues"], raw["required_changes"]
    if decision not in {"accept", "revise"} or not isinstance(issues, list) or not isinstance(changes, list):
        raise ValueError("review has invalid decision or list fields")
    if len(issues) > 2 or len(changes) > 2:
        raise ValueError("review exceeds the two-item limit")
    if not all(isinstance(value, str) and value.strip() for value in changes):
        raise ValueError("required_changes must contain non-empty strings")
    known_evidence = {item.evidence_id for item in case.evidence}
    allowed_targets = {f"C{i}" for i in range(1, len(assessment.accepted_claims) + 1)} | {f"A{i}" for i in range(1, len(assessment.recommended_actions) + 1)}
    parsed: list[dict[str, Any]] = []
    for issue in issues:
        if not isinstance(issue, Mapping) or set(issue) != {"issue_type", "target", "reason", "evidence_ids"}:
            raise ValueError("issue has an invalid schema")
        if issue["issue_type"] not in ISSUE_TYPES or issue["target"] not in allowed_targets:
            raise ValueError("issue type or target is not allowed")
        if not isinstance(issue["reason"], str) or not issue["reason"].strip() or len(issue["reason"]) > 180:
            raise ValueError("issue reason must be non-empty and within 180 characters")
        if _requests_out_of_scope_context(issue["issue_type"], issue["reason"]):
            raise ValueError("QA cannot require out-of-scope operational context")
        if not isinstance(issue["evidence_ids"], list) or not set(issue["evidence_ids"]).issubset(known_evidence):
            raise ValueError("issue cites unknown evidence")
        parsed.append(dict(issue))
    if bool(parsed) != (decision == "revise"):
        raise ValueError("decision must match whether issues were found")
    if decision == "accept" and changes:
        raise ValueError("accepted review cannot require changes")
    if not all(len(value) <= 140 for value in changes):
        raise ValueError("required change exceeds 140 characters")
    if any(_requests_out_of_scope_context("missing_uncertainty", value) for value in changes):
        raise ValueError("QA cannot require out-of-scope operational context")
    return QualityReview("accepted", decision, parsed, list(changes))


def _requests_out_of_scope_context(issue_type: Any, text: Any) -> bool:
    """Reject a critic request for evidence the product intentionally lacks."""
    if issue_type != "missing_uncertainty" or not isinstance(text, str):
        return False
    normalized = text.casefold()
    return any(term in normalized for term in _OUT_OF_SCOPE_CONTEXT_TERMS)
