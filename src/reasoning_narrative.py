"""Validation for short LLM analyst reasoning over reduced activity cards."""
from __future__ import annotations

import json
import re
from typing import Any, Mapping

try:
    from .case_models import InvestigationCase
    from .evidence_reduction import build_activity_cards
except ImportError:
    from case_models import InvestigationCase
    from evidence_reduction import build_activity_cards


_SPECIFIC_VALUE = re.compile(r"\{[0-9a-fA-F-]{8,}\}|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-zA-Z0-9.-]+\.(?:com|net|org|local|exe|dll|ps1)\b|[A-Za-z]:\\[^\s`\"]+", re.I)


def verify_narrative(case: InvestigationCase, value: Any) -> list[dict[str, Any]]:
    """Accept only short, cited reasoning with no uncited specific values.

    This is intentionally not a truth engine for natural language. It prevents
    the common harmful failure: a model introducing a host, IP, file, GUID, or
    domain which was never in the cited evidence packet. Semantic QA remains a
    separate optional critic stage.
    """
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 3:
        raise ValueError("narrative must contain at most three items")
    cards = {item["card_id"]: item for item in build_activity_cards(case)}
    accepted: list[dict[str, Any]] = []
    cited_card_ids: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"card_ids", "text"}:
            raise ValueError("narrative item has an invalid schema")
        card_ids, text = item["card_ids"], item["text"]
        if not isinstance(card_ids, list) or not card_ids or len(card_ids) > 4 or not all(isinstance(card_id, str) for card_id in card_ids) or len(set(card_ids)) != len(card_ids) or not set(card_ids).issubset(cards):
            raise ValueError("narrative item cites unknown activity cards")
        if not isinstance(text, str) or not 20 <= len(text.strip()) <= 500:
            raise ValueError("narrative text must be 20 to 500 characters")
        cited = json.dumps([cards[card_id] for card_id in card_ids], default=str).lower()
        for observed in _SPECIFIC_VALUE.findall(text):
            if observed.lower() not in cited:
                raise ValueError("narrative introduces an uncited specific value")
        accepted.append({"card_ids": card_ids, "text": text.strip()})
        cited_card_ids.update(card_ids)
    if accepted and any(card["kind"] not in {"seed_process", "direct_parent"} for card in cards.values()):
        if not any(cards[card_id]["kind"] not in {"seed_process", "direct_parent"} for card_id in cited_card_ids):
            raise ValueError("narrative must cite at least one correlated activity card")
    return accepted
