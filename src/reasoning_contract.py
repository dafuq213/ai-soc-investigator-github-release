"""Strict LLM reasoning contract and deterministic verification of atomic claims."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

try:
    from .case_models import InvestigationCase
except ImportError:
    from case_models import InvestigationCase


VERDICTS = {"likely_benign", "inconclusive", "suspicious_requires_review", "likely_malicious"}
CLAIM_TYPES = {"process_parent", "encoded_powershell", "network_connection", "authentication_window"}


@dataclass(frozen=True)
class AtomicClaim:
    claim_type: str
    evidence_ids: list[str]
    subject: str | None = None
    object: str | None = None


@dataclass(frozen=True)
class StructuredReasoning:
    verdict: str
    llm_confidence: float
    claims: list[AtomicClaim]
    benign_alternatives: list[str]
    unknowns: list[str]
    recommended_actions: list[dict[str, Any]]

    @classmethod
    def from_json(cls, payload: str | Mapping[str, Any]) -> "StructuredReasoning":
        raw = json.loads(payload) if isinstance(payload, str) else dict(payload)
        required = {"verdict", "llm_confidence", "claims", "benign_alternatives", "unknowns", "recommended_actions"}
        if set(raw) != required:
            raise ValueError("reasoning output has an invalid schema")
        if raw["verdict"] not in VERDICTS:
            raise ValueError("invalid verdict")
        confidence = raw["llm_confidence"]
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            raise ValueError("llm_confidence must be a number from 0 to 1")
        claims = [_claim(item) for item in _list_of_mappings(raw["claims"], "claims")]
        for name in ("benign_alternatives", "unknowns"):
            if not isinstance(raw[name], list) or not all(isinstance(item, str) and item.strip() for item in raw[name]):
                raise ValueError(f"{name} must be a list of non-empty strings")
        actions = _list_of_mappings(raw["recommended_actions"], "recommended_actions")
        return cls(raw["verdict"], float(confidence), claims, raw["benign_alternatives"], raw["unknowns"], actions)


@dataclass(frozen=True)
class ClaimVerification:
    claim: AtomicClaim
    accepted: bool
    reason: str


class ClaimVerifier:
    """Verifies typed claims from raw cited evidence; it never uses an LLM."""
    def verify(self, case: InvestigationCase, reasoning: StructuredReasoning) -> list[ClaimVerification]:
        evidence_by_id = {item.evidence_id: item for item in case.evidence}
        return [self._verify_claim(claim, evidence_by_id) for claim in reasoning.claims]

    def _verify_claim(self, claim: AtomicClaim, evidence_by_id: dict[str, Any]) -> ClaimVerification:
        records = [evidence_by_id[item].record for item in claim.evidence_ids if item in evidence_by_id]
        if len(records) != len(claim.evidence_ids):
            return ClaimVerification(claim, False, "claim cites an unknown evidence ID")
        if claim.claim_type == "process_parent":
            accepted = any(_win_field(record, "processGuid") == claim.subject and _win_field(record, "parentProcessGuid") == claim.object for record in records)
        elif claim.claim_type == "encoded_powershell":
            accepted = any("powershell" in (_win_field(record, "image") or "").lower() and "-encodedcommand" in (_win_field(record, "commandLine") or "").lower() for record in records)
        elif claim.claim_type == "network_connection":
            accepted = any(_win_field(record, "processGuid") == claim.subject and (_win_field(record, "destinationIp") or _path(record, "event", "destination", "ip")) == claim.object for record in records)
        elif claim.claim_type == "authentication_window":
            accepted = any(
                (_win_field(record, "targetUserName") or _win_field(record, "user")) == claim.subject
                and (_win_field(record, "ipAddress") or _win_field(record, "sourceIp") or _path(record, "event", "source", "ip")) == claim.object
                for record in records
            )
        else:  # Defensive: parsing already restricts this, retained for direct construction safety.
            accepted = False
        return ClaimVerification(claim, accepted, "supported by cited evidence" if accepted else "cited evidence does not support this typed claim")


def _claim(value: Mapping[str, Any]) -> AtomicClaim:
    if set(value) != {"claim_type", "evidence_ids", "subject", "object"}:
        raise ValueError("claim has an invalid schema")
    if value["claim_type"] not in CLAIM_TYPES:
        raise ValueError("unsupported claim type")
    if not isinstance(value["evidence_ids"], list) or not value["evidence_ids"] or not all(isinstance(item, str) for item in value["evidence_ids"]):
        raise ValueError("claim evidence_ids must be a non-empty list of strings")
    for name in ("subject", "object"):
        if value[name] is not None and not isinstance(value[name], str):
            raise ValueError(f"claim {name} must be a string or null")
    return AtomicClaim(value["claim_type"], value["evidence_ids"], value["subject"], value["object"])


def _list_of_mappings(value: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise ValueError(f"{name} must be a list of objects")
    return [dict(item) for item in value]


def _win_field(record: Mapping[str, Any], field: str) -> str | None:
    return _path(record, "event", "data", "win", "eventdata", field)


def _path(value: Any, *path: str) -> Any:
    current: Any = value
    for component in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(component)
    return current
