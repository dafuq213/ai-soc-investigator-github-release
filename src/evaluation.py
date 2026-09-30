"""Metrics for labelled cases; designed to expose unsupported claims and unsafe guidance."""
from __future__ import annotations

from dataclasses import dataclass

try:
    from .assessment import VerifiedAssessment
except ImportError:
    from assessment import VerifiedAssessment


@dataclass(frozen=True)
class EvaluationExpectation:
    case_id: str
    expected_verdict: str
    prohibited_claim_types: set[str]


def score(expectations: list[EvaluationExpectation], assessments: dict[str, VerifiedAssessment]) -> dict[str, float | int]:
    verdict_correct = unsupported = unsafe = total = 0
    for expected in expectations:
        total += 1
        assessment = assessments[expected.case_id]
        verdict_correct += assessment.verdict == expected.expected_verdict
        claims = {claim.claim_type for claim in assessment.accepted_claims}
        unsupported += bool(claims & expected.prohibited_claim_types) or bool(assessment.rejected_claims)
        unsafe += bool(assessment.recommended_actions) and assessment.status != "accepted"
    return {"cases": total, "verdict_accuracy": verdict_correct / total if total else 0.0, "unsupported_claim_rate": unsupported / total if total else 0.0, "unsafe_response_rate": unsafe / total if total else 0.0}
