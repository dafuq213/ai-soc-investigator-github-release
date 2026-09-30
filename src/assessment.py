"""Fail-closed bridge from structured LLM reasoning to user-visible assessment."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

try:
    from .case_models import InvestigationCase
    from .reasoning_contract import AtomicClaim, ClaimVerification, ClaimVerifier, StructuredReasoning
    from .assessment_dossier import compact_reasoning_to_legacy
    from .reasoning_narrative import verify_narrative
    from .judgment_contract import is_judgment_payload, resolve_judgment
except ImportError:
    from case_models import InvestigationCase
    from reasoning_contract import AtomicClaim, ClaimVerification, ClaimVerifier, StructuredReasoning
    from assessment_dossier import compact_reasoning_to_legacy
    from reasoning_narrative import verify_narrative
    from judgment_contract import is_judgment_payload, resolve_judgment


@dataclass(frozen=True)
class VerifiedAssessment:
    status: str
    verdict: str
    confidence: float
    accepted_claims: list[AtomicClaim]
    rejected_claims: list[ClaimVerification]
    benign_alternatives: list[str]
    unknowns: list[str]
    recommended_actions: list[dict[str, Any]]
    error: str | None = None
    # Retained in the case JSON for audit and provider troubleshooting.  It is
    # intentionally never rendered in the analyst report unless verified.
    raw_model_output: str | None = None
    quality_review: dict[str, Any] | None = None
    narrative: list[dict[str, Any]] | None = None
    # Selector-resolved analysis items from the compact assessor contract.
    # They are rendered only after the core assessment has passed verification.
    investigation_guidance: dict[str, Any] | None = None


class AssessmentPipeline:
    """Only an all-supported LLM assessment can be shown as an assessment."""
    def __init__(self, verifier: ClaimVerifier | None = None):
        self.verifier = verifier or ClaimVerifier()

    def evaluate(self, case: InvestigationCase, model_output: str | dict[str, Any]) -> VerifiedAssessment:
        try:
            raw = _as_mapping(model_output)
            guidance = None
            if is_judgment_payload(raw):
                compact, guidance = resolve_judgment(case, raw)
            else:
                compact = compact_reasoning_to_legacy(case, raw) if "confidence" in raw and "llm_confidence" not in raw else raw
            # Compact selector output is identified by its confidence band, not
            # by an optional ID array. The prompt explicitly permits omission
            # of empty arrays, so a valid no-claim response may contain only
            # verdict, confidence, and one selected action/unknown array.
            guidance = compact.pop("_analysis", guidance) if isinstance(compact, dict) else guidance
            reasoning = StructuredReasoning.from_json(compact)
        except (TypeError, ValueError) as exc:
            return self._rejected(error=f"invalid reasoning output: {exc}")
        outcomes = self.verifier.verify(case, reasoning)
        rejected = [item for item in outcomes if not item.accepted]
        if rejected:
            return self._rejected(rejected, "one or more claims were not supported by cited evidence")
        # A syntactically valid object with no claim, uncertainty, alternative,
        # or response advice is not reasoning.  Treat it as a provider failure
        # rather than giving it an "accepted" label in an analyst report.
        if not (reasoning.claims or reasoning.benign_alternatives or reasoning.unknowns or reasoning.recommended_actions or (isinstance(guidance, dict) and guidance.get("sections"))):
            return self._rejected(error="model returned an empty assessment")
        actions_error = _validate_recommendations(case, reasoning.recommended_actions)
        if actions_error:
            return self._rejected(error=actions_error)
        try:
            narrative = verify_narrative(case, raw.get("narrative"))
        except ValueError:
            # A narrative is optional presentation content. Do not let an
            # unsafe sentence become visible simply because the structured
            # assessment itself was valid.
            narrative = []
        return VerifiedAssessment(
            status="accepted",
            verdict=reasoning.verdict,
            confidence=reasoning.llm_confidence,
            accepted_claims=[item.claim for item in outcomes],
            rejected_claims=[],
            benign_alternatives=reasoning.benign_alternatives,
            unknowns=reasoning.unknowns,
            recommended_actions=reasoning.recommended_actions,
            narrative=narrative,
            investigation_guidance=guidance if isinstance(guidance, dict) else None,
        )

    @staticmethod
    def evidence_only() -> VerifiedAssessment:
        """Represent an intentional no-model run without treating it as a model failure."""
        return VerifiedAssessment(
            status="evidence_only", verdict="inconclusive", confidence=0.0,
            accepted_claims=[], rejected_claims=[], benign_alternatives=[],
            unknowns=["No LLM assessment was requested; this is an evidence-only triage report."],
            recommended_actions=[], error=None,
        )

    @staticmethod
    def _rejected(rejected: list[ClaimVerification] | None = None, error: str | None = None) -> VerifiedAssessment:
        return VerifiedAssessment(
            status="rejected", verdict="inconclusive", confidence=0.0,
            accepted_claims=[], rejected_claims=rejected or [], benign_alternatives=[],
            unknowns=["LLM assessment was not accepted; review the recorded evidence directly."],
            recommended_actions=[], error=error,
        )


def evaluate_with_model(case: InvestigationCase, produce: Callable[[InvestigationCase], str], pipeline: AssessmentPipeline | None = None) -> VerifiedAssessment:
    """Inject a provider later; provider failure remains a rejected assessment."""
    try:
        output = produce(case)
    except Exception as exc:
        return AssessmentPipeline._rejected(error=f"model provider failed: {exc}")
    assessment = (pipeline or AssessmentPipeline()).evaluate(case, output)
    return replace(assessment, raw_model_output=output)


def _validate_recommendations(case: InvestigationCase, actions: list[dict[str, Any]]) -> str | None:
    known = {item.evidence_id for item in case.evidence}
    allowed = {"preserve_evidence", "validate_change", "isolate_host", "disable_user", "block_ip"}
    for action in actions:
        if set(action) != {"action", "reason", "risk", "evidence_ids"}:
            return "recommendation has an invalid schema"
        if action["action"] not in allowed:
            return "recommendation action is not allowed"
        if not isinstance(action["reason"], str) or not action["reason"].strip() or not isinstance(action["risk"], str) or not action["risk"].strip():
            return "recommendation requires non-empty reason and risk"
        if not isinstance(action["evidence_ids"], list) or not action["evidence_ids"] or not set(action["evidence_ids"]).issubset(known):
            return "recommendation requires known evidence IDs"
        records = [item.record for item in case.evidence if item.evidence_id in action["evidence_ids"]]
        if action["action"] == "isolate_host" and not any(_has_network_indicator(record) for record in records):
            return "host isolation requires cited network evidence"
        if action["action"] == "block_ip" and not any(_has_network_indicator(record) for record in records):
            return "IP blocking requires cited network evidence"
        if action["action"] == "disable_user" and not any(_has_user_indicator(record) for record in records):
            return "user disablement requires cited user evidence"
    return None


def _as_mapping(model_output: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(model_output, str):
        value = model_output.strip()
        fenced = re.fullmatch(r"```(?:json)?\s*(\{.*\})\s*```", value, flags=re.DOTALL | re.IGNORECASE)
        raw = json.loads(fenced.group(1) if fenced else value)
    else:
        raw = dict(model_output)
    if not isinstance(raw, dict):
        raise ValueError("reasoning output must be an object")
    return raw


def _has_network_indicator(record: Mapping[str, Any]) -> bool:
    event = record.get("event", {})
    if not isinstance(event, Mapping):
        return False
    win = event.get("data", {}).get("win", {}).get("eventdata", {})
    if isinstance(win, Mapping) and (win.get("destinationIp") or win.get("sourceIp")):
        return True
    return bool(event.get("destination", {}).get("ip") or event.get("source", {}).get("ip")) if isinstance(event.get("destination", {}), Mapping) and isinstance(event.get("source", {}), Mapping) else False


def _has_user_indicator(record: Mapping[str, Any]) -> bool:
    event = record.get("event", {})
    if not isinstance(event, Mapping):
        return False
    win = event.get("data", {}).get("win", {}).get("eventdata", {})
    if isinstance(win, Mapping) and any(win.get(key) for key in ("user", "targetUserName", "subjectUserName")):
        return True
    user = event.get("user", {})
    return isinstance(user, Mapping) and bool(user.get("name"))
