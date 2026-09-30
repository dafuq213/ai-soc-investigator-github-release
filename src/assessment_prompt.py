"""Prompt construction for the evidence-grounded assessment model boundary."""
from __future__ import annotations

import json
from typing import Any

try:
    from .case_models import InvestigationCase
    from .assessment_dossier import build_dossier
except ImportError:
    from case_models import InvestigationCase
    from assessment_dossier import build_dossier


def assessment_prompt(case: InvestigationCase) -> str:
    """Return a small dossier with stable labels instead of raw event copies."""
    dossier = build_dossier(case)
    return f"""You are a SOC investigator. Assess only the standardized dossier below.
Return exactly one JSON object; no markdown or extra keys. This is the
`judgment_v2` contract: every listed key is required, and empty arrays must be
included where no cited factor applies.

{json.dumps(_valid_example(dossier), separators=(',', ':'))}

Rules:
- Select IDs only from the listed options. Never invent an ID, fact, user, host, IP, process, MITRE technique, or response action.
- The JSON above illustrates the schema only. Do not copy its narrative text: write each sentence from the cited dossier observation or activity card.
- `verdict` must be one of likely_benign, inconclusive, suspicious_requires_review, or likely_malicious. `confidence` must be an integer from 0 to 100.
- `claim_verification_id` must select the status shown in `alert_claim`; a Wazuh title is a trigger, not independent proof of the title's wording.
- `next_check_id` must select exactly one option from `next_check_options`; do not invent a query, control, response action, change record, or intelligence source.
- `what_happened` and `alert_claim_assessment` each require one or two cited items. Other narrative arrays may be empty or contain up to two cited items.
- A narrative item must contain exactly `refs` and `text`. `refs` selects one to four IDs from activity cards (`R##`) or derived observations (`D##`). Use derived observations to explain literal operations in plain language.
- `reassuring_factors` and `concern_factors` are competing evidence-backed hypotheses, not facts of legitimacy or compromise.
- Missing data is never a reassuring or concern factor. Put missing/unknown context only in `evidence_gap_ids`; never cite a `U##` identifier in a narrative `refs` list.
- likely_benign requires a cited reassuring factor. likely_malicious requires at least two independent cited concern references and confidence of at least 60. Confidence cannot exceed the evidence cap enforced by the verifier.
- Do not infer intent, authorization, outcome, privilege, or the security meaning of an access mask. Do not call activity normal or malicious solely from a process name, path, user, or alert title.
- `evidence_gap_ids` selects only listed unknown options. `action_ids` selects only listed controlled actions; do not select containment.

STANDARDIZED DOSSIER:
{json.dumps(dossier, separators=(",", ":"), default=str)}
"""


def _valid_example(dossier: dict[str, Any]) -> dict[str, Any]:
    """Generate an example that cannot introduce nonexistent card selectors."""
    refs = []
    observations = dossier.get("derived_observations", [])
    if isinstance(observations, list) and observations and isinstance(observations[0], dict):
        refs = [observations[0].get("id")]
    if not refs:
        cards = dossier.get("activity_cards", [])
        if isinstance(cards, list) and cards and isinstance(cards[0], dict):
            refs = [cards[0].get("card_id")]
    example: dict[str, Any] = {
        "verdict": "inconclusive",
        "confidence": 35,
        "claim_verification_id": "V01",
        "what_happened": [{"refs": refs, "text": "The cited observation records activity; it does not establish intent or outcome."}],
        "alert_claim_assessment": [{"refs": refs, "text": "The Wazuh alert is a detection trigger; the cited observation is the available evidence for review."}],
        "reassuring_factors": [],
        "concern_factors": [],
        "competing_hypotheses": [],
        "evidence_gap_ids": [],
        "next_check_id": "N01",
        "action_ids": ["A01"],
    }
    return example
