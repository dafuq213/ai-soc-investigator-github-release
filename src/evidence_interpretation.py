"""Bounded, evidence-cited plain-language interpretation for analyst reports.

This is deliberately separate from assessment: an interpretation explains the
meaning of an observed command or relationship, but it cannot introduce a
new fact, verdict, entity, or response action.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

try:
    from .assessment_dossier import build_dossier
    from .case_models import InvestigationCase
except ImportError:
    from assessment_dossier import build_dossier
    from case_models import InvestigationCase


@dataclass(frozen=True)
class EvidenceInterpretation:
    status: str
    items: list[dict[str, str]]
    error: str | None = None
    raw_model_output: str | None = None


def interpretation_prompt(case: InvestigationCase) -> str:
    """Build the exact, selector-only prompt for explanatory LLM stage.

    Free-text explanations looked natural but allowed a local model to invent
    elevated privileges in a live replay.  The LLM therefore selects a known,
    evidence-derived interpretation and Python renders its wording.
    """
    options = interpretation_options(case)
    return f"""You are a SOC investigator. Select useful explanations of the observed evidence.
Return exactly one JSON object and no markdown: {{"interpretation_ids":["I01"]}}.

Rules:
- Select only IDs listed in OPTIONS. Do not invent an ID, fact, host, user, privilege, outcome, MITRE technique, verdict, or response action.
- Select at most two IDs. An empty list is allowed.
- The selected explanation is an interpretation of cited observations, not proof of intent, compromise, or execution success.

OPTIONS:
{json.dumps(options, separators=(",", ":"), default=str)}
"""


def interpretation_options(case: InvestigationCase) -> list[dict[str, str]]:
    """Offer only explanations whose preconditions are observed in evidence.

    This is a growing capability catalog, not a per-alert playbook: unsupported
    command semantics are deliberately left unexplained rather than guessed.
    """
    options: list[dict[str, str]] = []
    for fact in build_dossier(case)["facts"]:
        text = fact["text"]
        lowered = text.lower()
        if text.startswith("Observed command:") and "whoami" in lowered:
            options.append({
                "id": "I01", "evidence_id": fact["evidence_id"],
                "text": "The observed `whoami /all` command requests the current Windows account identity and, with `/all`, its group, privilege, and SID details.",
            })
        if text.startswith("Decoded command:") and "whoami" in lowered:
            options.append({
                "id": "I02", "evidence_id": fact["evidence_id"],
                "text": "The decoded command includes `whoami`, which requests the current Windows account identity; the collected command text does not prove what happened after execution.",
            })
    return options


def verify_interpretation(case: InvestigationCase, model_output: str | Mapping[str, Any]) -> EvidenceInterpretation:
    """Fail closed on anything outside the limited explanatory contract."""
    try:
        raw = json.loads(model_output) if isinstance(model_output, str) else dict(model_output)
        if set(raw) != {"interpretation_ids"} or not isinstance(raw["interpretation_ids"], list):
            raise ValueError("interpretation has an invalid schema")
        if len(raw["interpretation_ids"]) > 2:
            raise ValueError("interpretation contains too many items")
        options = {item["id"]: item for item in interpretation_options(case)}
        items: list[dict[str, str]] = []
        seen: set[str] = set()
        for interpretation_id in raw["interpretation_ids"]:
            if not isinstance(interpretation_id, str) or interpretation_id not in options or interpretation_id in seen:
                raise ValueError("interpretation contains an unknown or duplicate ID")
            seen.add(interpretation_id)
            option = options[interpretation_id]
            items.append({"interpretation_id": interpretation_id, "evidence_id": option["evidence_id"], "text": option["text"]})
        return EvidenceInterpretation(status="accepted", items=items, raw_model_output=model_output if isinstance(model_output, str) else json.dumps(raw))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return EvidenceInterpretation(status="rejected", items=[], error=str(exc), raw_model_output=model_output if isinstance(model_output, str) else json.dumps(model_output, default=str))
