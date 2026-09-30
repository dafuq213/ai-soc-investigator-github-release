"""Reduce verified case evidence into a small, auditable analyst packet.

Reduction is deterministic: it groups repeated observations but never assigns a
benign or malicious meaning.  Every card retains the original evidence IDs.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping

try:
    from .case_models import InvestigationCase
except ImportError:
    from case_models import InvestigationCase


_EVENT_LABELS = {
    "3": "network connection", "7": "image load", "11": "file operation",
    "12": "registry operation", "13": "registry operation", "14": "registry operation",
    "22": "DNS query",
}

_RELATIONSHIP_LABELS = {
    "same_seed_process": "same seed process",
    "process_creation_observed": "process-create event observed",
    "process_creation_unavailable": "process-create event unavailable",
}


def build_activity_cards(case: InvestigationCase, max_cards: int = 12) -> list[dict[str, Any]]:
    """Return a bounded, de-duplicated activity view for an LLM or report."""
    cards: list[dict[str, Any]] = []
    seed = case.evidence[0] if case.evidence else None
    if seed:
        fields = _fields(seed.record)
        cards.append(_card("R01", "seed_process", [seed.evidence_id], {
            "host": seed.record.get("host") or "unknown",
            "image": fields.get("image") or "unknown",
            "command_line": _short(fields.get("commandLine"), 500),
            # These human-readable provenance fields are evidence, not
            # correlation implementation keys.  Keeping them on the seed card
            # lets a cited narrative explain a launch context without copying
            # a ProcessGuid into an LLM prompt or report.
            "parent_image": fields.get("parentImage") or fields.get("sourceImage") or "unknown",
            "user": fields.get("user") or fields.get("targetUserName") or "unknown",
            "process_guid": fields.get("processGuid") or "unknown",
        }, "Observed seed process."))

    tree = case.correlations.get("process_tree", {}) if isinstance(case.correlations, Mapping) else {}
    nodes = tree.get("nodes", {}) if isinstance(tree, Mapping) else {}
    if seed:
        parent_guid = _fields(seed.record).get("parentProcessGuid")
        parent = nodes.get(parent_guid) if isinstance(nodes, Mapping) else None
        if isinstance(parent, Mapping):
            cards.append(_card("R02", "direct_parent", list(parent.get("evidence_ids", [])), {
                "image": parent.get("image") or "unknown",
                "process_guid": parent_guid,
            }, "Observed direct parent process."))

    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for relation in case.correlations.get("sysmon_relationships", []) if isinstance(case.correlations, Mapping) else []:
        if not isinstance(relation, Mapping):
            continue
        if relation.get("relationship") == "process_access":
            key = ("process_access", relation.get("source_process_guid"), relation.get("target_process_guid"), relation.get("granted_access"), relation.get("source_relationship"), relation.get("target_relationship"))
        else:
            event_id = str(relation.get("event_id", ""))
            if event_id not in _EVENT_LABELS:
                continue
            # A registry sequence commonly contains key creation, value set,
            # and rename events. Its individual paths belong in the evidence
            # appendix, while one card is sufficient for assessment.
            affected = relation.get("affected_object") if event_id not in {"12", "13", "14"} else "registry_sequence"
            key = (event_id if event_id not in {"12", "13", "14"} else "registry", relation.get("process_guid"), affected, relation.get("status"))
        grouped[key].append(relation)

    for key, items in grouped.items():
        evidence_ids = sorted({str(item.get("evidence_id")) for item in items if item.get("evidence_id")})
        if key[0] == "process_access":
            _, source, target, access, source_relationship, target_relationship = key
            cards.append(_card("", "process_access", evidence_ids, {
                "source_process": _process_name(items[0].get("source_process_image")),
                "target_process": _process_name(items[0].get("target_process_image")),
                "granted_access": access or "not recorded", "occurrences": len(items),
                "source_relationship": _relationship_label(source_relationship),
                "target_relationship": _relationship_label(target_relationship),
            }, "Observed process-access relationship(s)."))
        else:
            event_id, process_guid, affected, status = key
            is_registry = event_id == "registry"
            kind = "registry operation" if is_registry else _EVENT_LABELS[event_id]
            observed = {
                "process": _process_name(items[0].get("process_image")), "occurrences": len(items),
                "process_relationship": _relationship_label(status),
                "process_creation_context": _relationship_label(
                    "process_creation_observed" if items[0].get("process_creation_status") == "observed" else "process_creation_unavailable"
                ),
            }
            if is_registry:
                observed["event_ids"] = sorted({str(item.get("event_id")) for item in items})
                observed["affected_objects"] = sorted({str(item.get("affected_object")) for item in items if item.get("affected_object")})[:4]
            else:
                observed.update({"event_id": event_id, "affected_object": affected or "not recorded"})
            cards.append(_card("", kind, evidence_ids, observed, f"Observed {kind} relationship(s)."))

    # Seed/parent stay first; the rest are stable by kind and object so replay
    # produces the same packet regardless of OpenSearch result ordering.
    head, tail = cards[:2], cards[2:]
    tail.sort(key=lambda item: (item["kind"], str(item["observed"])))
    ordered = (head + tail)[:max_cards]
    for index, item in enumerate(ordered, start=1):
        item["card_id"] = f"R{index:02d}"
    return ordered


def _card(card_id: str, kind: str, evidence_ids: list[str], observed: dict[str, Any], text: str) -> dict[str, Any]:
    return {"card_id": card_id, "kind": kind, "evidence_ids": evidence_ids, "observed": observed, "text": text}


def _fields(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return record.get("event", {}).get("data", {}).get("win", {}).get("eventdata", {}) if isinstance(record.get("event"), Mapping) else {}


def _short(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value if len(value) <= limit else value[:limit] + "…[truncated]"


def _process_name(value: Any) -> str:
    """Render a process identity for people; GUIDs remain in case correlation."""
    if not isinstance(value, str) or not value:
        return "unresolved"
    return value.rsplit("\\", 1)[-1]


def _relationship_label(value: Any) -> str:
    return _RELATIONSHIP_LABELS.get(str(value), "relationship not recorded")
