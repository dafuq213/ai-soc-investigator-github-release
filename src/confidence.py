"""Explainable pre-calibration confidence inputs; not an LLM self-rating."""
from __future__ import annotations

from dataclasses import dataclass

try:
    from .assessment import VerifiedAssessment
except ImportError:
    from assessment import VerifiedAssessment


@dataclass(frozen=True)
class ConfidenceResult:
    score: float
    inputs: dict[str, float]


def calculate_confidence(assessment: VerifiedAssessment) -> ConfidenceResult:
    if assessment.status != "accepted":
        return ConfidenceResult(0.0, {"assessment_accepted": 0.0})
    claim_strength = min(len(assessment.accepted_claims) * 0.15, 0.45)
    uncertainty_penalty = min(len(assessment.unknowns) * 0.08, 0.24)
    model_component = assessment.confidence * 0.25
    score = max(0.0, min(1.0, 0.25 + claim_strength + model_component - uncertainty_penalty))
    return ConfidenceResult(round(score, 3), {"verified_claim_strength": claim_strength, "llm_component": model_component, "unknown_penalty": -uncertainty_penalty})
