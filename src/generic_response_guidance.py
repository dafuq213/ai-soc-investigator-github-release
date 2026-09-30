"""Render already validated, model-written recommendations without executing them."""
from __future__ import annotations

from typing import Any, Mapping

def build_response_proposals(packet: Mapping[str, Any], assessment: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return bounded recommendations after the assessment contract accepted them."""
    requested = assessment.get("recommended_actions")
    if not isinstance(requested, list):
        return []
    proposals: list[dict[str, Any]] = []
    for item in requested:
        if not isinstance(item, Mapping):
            continue
        category = item.get("category")
        if category not in {"investigate", "validate_context", "preserve_evidence", "escalate", "consider_response"}:
            continue
        proposals.append({
            "category": category,
            "action": item.get("action"),
            "reason": item.get("reason"),
            "evidence_ids": item.get("evidence_ids", []),
            "target": item.get("target"),
            "priority": item.get("priority"),
            "executed": False,
            "requires_human_approval": category == "consider_response",
        })
    return proposals
