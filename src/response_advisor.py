"""Evidence-gated V1 response guidance. This module never executes changes."""
from __future__ import annotations

from dataclasses import dataclass

try:
    from .assessment import VerifiedAssessment
    from .confidence import ConfidenceResult
except ImportError:
    from assessment import VerifiedAssessment
    from confidence import ConfidenceResult


@dataclass(frozen=True)
class ResponseGuidance:
    action: str
    reason: str
    risk: str
    approval_required: bool = True


def advise(assessment: VerifiedAssessment, confidence: ConfidenceResult) -> list[ResponseGuidance]:
    if assessment.status != "accepted" or assessment.verdict != "suspicious_requires_review":
        return []
    guidance = [ResponseGuidance("preserve_evidence", "Preserve relevant process, command-line, and network evidence before it expires.", "Collection may consume storage and analyst time.")]
    types = {claim.claim_type for claim in assessment.accepted_claims}
    if confidence.score >= 0.7 and "network_connection" in types:
        guidance.append(ResponseGuidance("isolate_host", "Verified suspicious execution includes a process-linked network connection.", "The user may lose network access and business operations may be interrupted."))
    return guidance
