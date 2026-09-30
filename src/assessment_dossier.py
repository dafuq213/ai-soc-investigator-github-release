"""Small, non-duplicative evidence dossier for the investigation LLM."""
from __future__ import annotations

from typing import Any, Mapping

try:
    from .case_models import InvestigationCase
    from .evidence_reduction import build_activity_cards
    from .sysmon_profile_contracts import contract_for_event_id
except ImportError:
    from case_models import InvestigationCase
    from evidence_reduction import build_activity_cards
    from sysmon_profile_contracts import contract_for_event_id


def build_dossier(case: InvestigationCase) -> dict[str, Any]:
    """Create the only evidence view used by the assessment LLM.

    It intentionally omits raw event blobs, Base64 commands, entity inventories,
    and the full correlation graph.  All IDs map back to verifier-controlled
    objects; the model selects labels instead of copying process GUIDs.
    """
    seed = case.evidence[0] if case.evidence else None
    facts: list[dict[str, str]] = []
    claims: list[dict[str, Any]] = []
    unknowns: list[dict[str, str]] = []
    benign: list[dict[str, str]] = []
    if seed:
        event = _eventdata(seed.record)
        description = seed.record.get("rule", {}).get("description") if isinstance(seed.record.get("rule"), Mapping) else None
        facts.append({"id": "F01", "evidence_id": seed.evidence_id, "text": f"Trigger: {_safe_text(description, 240, 'Wazuh seed event')} on host {_safe_text(seed.record.get('host'), 128, 'unknown')}."})
        command_line = _safe_text(event.get("commandLine"), 600, "")
        if command_line and not _is_encoded_powershell(event):
            # Retained as a separate stable fact because the constrained
            # command-explanation stage cites it directly.
            facts.append({"id": f"F{len(facts)+1:02d}", "evidence_id": seed.evidence_id, "text": f"Observed command: {command_line}"})
        if _is_encoded_powershell(event):
            claims.append({"id": "C01", "claim_type": "encoded_powershell", "evidence_ids": [seed.evidence_id]})
        if event.get("processGuid") and event.get("parentProcessGuid"):
            claims.append({"id": "C02", "claim_type": "process_parent", "evidence_ids": [seed.evidence_id]})
        if event.get("processGuid") and not event.get("parentProcessGuid"):
            unknowns.append({"id": "U06", "text": "The seed process has no ParentProcessGuid, so parent origin cannot be determined from this record."})
        _add_sysmon_seed_fact(seed.evidence_id, event, _system(seed.record), facts)
    profile_observation = _profile_observation(case)
    if profile_observation:
        # Telemetry can show what occurred but this lab deliberately has no
        # change-management or allowlist integration.  Make that boundary
        # explicit rather than asking a model to imply authorization from a
        # process name, path, or user.
        unknowns.append({
            "id": "U08",
            "text": "No change record, approved automation identity, or expected-activity context was collected; authorization cannot be determined from telemetry alone.",
        })
    auth_items = [item for item in case.evidence if item.event_type == "authentication"]
    if auth_items:
        _add_authentication_cards(auth_items, facts, claims, benign, unknowns)
    for item in case.evidence:
        if item.event_type == "decoded_powershell":
            command = item.record.get("decoded_command")
            if command:
                facts.append({"id": f"F{len(facts)+1:02d}", "evidence_id": item.evidence_id, "text": f"Decoded command: {_safe_text(command, 600, 'not recorded')}"})
                benign.append({"id": "B01", "text": "The decoded command may be an administrative connectivity test; collected evidence contains no authorization context."})
    direct_parent = _direct_parent_summary(case)
    if direct_parent:
        facts.append({"id": f"F{len(facts)+1:02d}", "evidence_id": direct_parent[0], "text": direct_parent[1]})
    # Reports retain the detailed cards for an analyst.  The model does not
    # need opaque process GUIDs to assess an observed relationship, so its
    # dossier receives the same card identities with an intentionally smaller
    # observed-value view.
    activity_cards = _llm_activity_cards(build_activity_cards(case))
    if any(
        card.get("observed", {}).get("process_creation_context") == "process-create event unavailable"
        or card.get("observed", {}).get("source_relationship") == "process-create event unavailable"
        or card.get("observed", {}).get("target_relationship") == "process-create event unavailable"
        for card in activity_cards
    ):
        unknowns.append({"id": "U07", "text": "Some Sysmon process references could not be resolved to a collected process-creation record."})
    for tool in case.tool_history:
        if tool.get("tool") == "get_process_network_activity":
            if tool.get("count", 0) == 0:
                unknowns.append({"id": "U01", "text": "No process-linked network telemetry was returned; command text does not prove connection success."})
        if tool.get("tool") == "get_process_children" and tool.get("count", 0) == 0:
            unknowns.append({"id": "U02", "text": "No direct child process telemetry was returned for the seed process."})
    tree = case.correlations.get("process_tree", {}) if isinstance(case.correlations, Mapping) else {}
    if tree.get("unresolved_parent_guids"):
        unknowns.append({"id": "U03", "text": "The earlier parent process is not available in the collected telemetry."})
    context = _context_summary(case)
    if context:
        facts.append({"id": f"X{len(facts)+1:02d}", "evidence_id": "context", "text": context})
    return {
        "case_id": case.case_id,
        "trigger": _trigger_metadata(case),
        "alert_claim": _alert_claim(case),
        "profile_observation": profile_observation,
        "derived_observations": _derived_observations(case),
        "facts": facts,
        "activity_cards": activity_cards,
        "claim_options": claims,
        "benign_options": benign,
        "unknown_options": _dedupe_by_id(unknowns),
        "action_options": [
            {"id": "A01", "action": "preserve_evidence"},
            {"id": "A02", "action": "validate_change"},
        ],
        "next_check_options": _next_check_options(case),
    }


def _trigger_metadata(case: InvestigationCase) -> dict[str, Any]:
    """Preserve Wazuh's detection statement without treating it as verified."""
    seed = case.evidence[0] if case.evidence else None
    if not seed:
        return {"source": "Wazuh", "title": None, "rule_id": None, "severity": None, "mitre": {}}
    rule = seed.record.get("rule", {}) if isinstance(seed.record.get("rule"), Mapping) else {}
    return {
        "source": "Wazuh",
        "title": _safe_text(rule.get("description"), 240, None),
        "rule_id": _safe_text(rule.get("id"), 64, None),
        "severity": rule.get("level"),
        "mitre": _safe_mitre(rule.get("mitre")),
        "evidence_id": seed.evidence_id,
        "status": "detection_trigger_not_analyst_conclusion",
    }


def _alert_claim(case: InvestigationCase) -> dict[str, str]:
    """Keep a detection statement distinct from independently observed facts.

    A Wazuh rule description is a valuable triage signal, but it is not proof
    of every phrase in its human-readable title.  A profile may later provide
    corroborating evidence; the generic V1 contract never assumes that it did.
    """
    trigger = _trigger_metadata(case)
    title = trigger.get("title") or "Wazuh detection"
    return {
        "status_id": "V01",
        "status": "not_independently_verified",
        "text": f"Wazuh raised the detection: {title}. The title is a detection trigger and is not independently verified solely by this label.",
    }


def _derived_observations(case: InvestigationCase) -> list[dict[str, str]]:
    """Produce small, source-linked operation facts for any alert family.

    These are syntax/field observations, not threat intelligence.  They give a
    model something concrete to explain even when an alert has no Sysmon
    profile, while bounded field choices prevent raw-event prompt bloat.
    """
    items: list[dict[str, str]] = []
    for evidence in case.evidence[:4]:
        event = _eventdata(evidence.record)
        system = _system(evidence.record)
        fields: list[tuple[str, str]] = []
        event_id = str(system.get("eventID", ""))
        if event_id == "10" and event.get("sourceImage") and event.get("targetImage"):
            access = _safe_text(event.get("grantedAccess"), 32, "not recorded")
            fields.append(("process_access", f"Observed process access: {_safe_text(event.get('sourceImage'), 180, 'unknown')} accessed {_safe_text(event.get('targetImage'), 180, 'unknown')}; granted access={access}."))
        elif event_id == "3" and event.get("image") and event.get("destinationIp"):
            port = _safe_text(event.get("destinationPort"), 16, None)
            suffix = f":{port}" if port else ""
            fields.append(("network", f"Observed network connection: {_safe_text(event.get('image'), 180, 'unknown')} connected to {_safe_text(event.get('destinationIp'), 80, 'unknown')}{suffix}."))
        elif event_id in {"12", "13", "14"} and event.get("targetObject"):
            fields.append(("registry", f"Observed registry operation target: {_safe_text(event.get('targetObject'), 240, 'unknown')}."))
        elif event_id == "11" and event.get("targetFilename"):
            fields.append(("file", f"Observed file operation target: {_safe_text(event.get('targetFilename'), 240, 'unknown')}."))
        elif event_id == "22" and event.get("queryName"):
            fields.append(("dns", f"Observed DNS query: {_safe_text(event.get('queryName'), 240, 'unknown')}."))
        image = _safe_text(event.get("image"), 180, None)
        command = _safe_text(event.get("commandLine"), 360, None)
        if image:
            fields.append(("process", f"Observed process image: {image}."))
        if command and not _is_encoded_powershell(event):
            fields.append(("command", f"Observed command line: {command}"))
        for name, label in (
            ("targetObject", "registry target"), ("targetFilename", "file target"),
            ("imageLoaded", "loaded image"), ("queryName", "DNS query"),
        ):
            value = _safe_text(event.get(name), 240, None)
            if value:
                fields.append((name, f"Observed {label}: {value}."))
        destination = _safe_text(event.get("destinationIp"), 80, None)
        port = _safe_text(event.get("destinationPort"), 16, None)
        if destination:
            suffix = f":{port}" if port else ""
            fields.append(("network", f"Observed network destination: {destination}{suffix}."))
        if not fields:
            event_id = _safe_text(system.get("eventID"), 16, None)
            event_type = _safe_text(evidence.event_type, 80, "alert event")
            fields.append(("event", f"Observed {event_type}{f' (event ID {event_id})' if event_id else ''}; no supported operation field was retained in the compact dossier."))
        for _kind, text in fields[:3]:
            items.append({"id": f"D{len(items)+1:02d}", "evidence_id": evidence.evidence_id, "text": text})
            if len(items) >= 8:
                return items
    return items


def _next_check_options(case: InvestigationCase) -> list[dict[str, str]]:
    """Offer evidence collection checks, never unchecked containment actions."""
    options = [{"id": "N01", "text": "Preserve the cited alert and correlated telemetry before retention expires."}]
    seed = case.evidence[0] if case.evidence else None
    event = _eventdata(seed.record) if seed else {}
    if event.get("parentProcessGuid"):
        options.append({"id": "N02", "text": "Collect the direct parent process-create record to validate the observed launch chain."})
    if any(key in event for key in ("targetObject", "targetFilename", "image", "commandLine")):
        options.append({"id": "N03", "text": "Collect the matching operation event or source record needed to independently verify the Wazuh detection claim."})
    return options[:3]


def _profile_observation(case: InvestigationCase) -> dict[str, Any] | None:
    """Return the exact, compact profile values supplied to the assessor.

    Correlation keys remain inside the controlled collector/case audit trail.
    The model receives only named dossier fields from the selected contract.
    """
    seed = case.evidence[0] if case.evidence else None
    if seed is None:
        return None
    system = _system(seed.record)
    contract = contract_for_event_id(str(system.get("eventID", "")))
    if contract is None:
        return None
    values = contract.values(_eventdata(seed.record))
    if contract.event_id == "1" and _is_encoded_powershell(_eventdata(seed.record)):
        values.pop("command_line", None)
    return {
        "event_id": contract.event_id,
        "profile_id": contract.profile_id,
        "fields": {key: _llm_observed(value) for key, value in values.items() if value not in (None, "")},
    }


def compact_reasoning_to_legacy(case: InvestigationCase, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve model-selected labels into the existing verifier contract."""
    allowed = {"verdict", "confidence", "claim_ids", "benign_ids", "unknown_ids", "action_ids", "narrative", "claim_verification_id", "next_check_id"}
    if not {"verdict", "confidence"}.issubset(payload) or not set(payload).issubset(allowed):
        raise ValueError("compact reasoning has an invalid schema")
    if payload["verdict"] not in {"inconclusive", "suspicious_requires_review"}:
        raise ValueError("compact reasoning has an invalid verdict")
    if payload["confidence"] not in {"low", "medium", "high"}:
        raise ValueError("compact reasoning has an invalid confidence band")
    dossier = build_dossier(case)
    options = {item["id"]: item for item in dossier["claim_options"]}
    benign = {item["id"]: item["text"] for item in dossier["benign_options"]}
    unknowns = {item["id"]: item["text"] for item in dossier["unknown_options"]}
    actions = {item["id"]: item["action"] for item in dossier["action_options"]}
    claim_ids = payload.get("claim_ids", [])
    benign_ids = payload.get("benign_ids", [])
    unknown_ids = payload.get("unknown_ids", [])
    action_ids = payload.get("action_ids", [])
    _known_list(claim_ids, options, "claim_ids")
    _known_list(benign_ids, benign, "benign_ids")
    _known_list(unknown_ids, unknowns, "unknown_ids")
    # Small local models sometimes return the displayed action name rather
    # than its short selector ID. Both are allowlisted representations of the
    # same controlled action; unknown values still fail closed.
    action_name_to_id = {value: key for key, value in actions.items()}
    if isinstance(action_ids, list):
        action_ids = [action_name_to_id.get(item, item) for item in action_ids]
    _known_list(action_ids, actions, "action_ids")
    verification_options = {item["status_id"]: item for item in [dossier["alert_claim"]]}
    verification_id = payload.get("claim_verification_id")
    if verification_id not in verification_options:
        raise ValueError("claim_verification_id contains an unknown option")
    next_checks = {item["id"]: item["text"] for item in dossier["next_check_options"]}
    next_check_id = payload.get("next_check_id")
    if next_check_id not in next_checks:
        raise ValueError("next_check_id contains an unknown option")
    claims = [_expand_claim(case, options[item]) for item in claim_ids]
    evidence_ids = _seed_evidence_ids(case)
    recommendations = [_action(actions[item], evidence_ids, case) for item in action_ids]
    selected_unknowns = [unknowns[item] for item in unknown_ids]
    # Data-source coverage is a fact, not a model opinion. Preserve every
    # observed evidence gap so a concise model answer cannot inflate case
    # confidence merely by omitting it.
    all_unknowns = list(dict.fromkeys(selected_unknowns + list(unknowns.values())))
    result = {
        "verdict": payload["verdict"], "llm_confidence": {"low": 0.35, "medium": 0.6, "high": 0.8}[payload["confidence"]],
        "claims": claims, "benign_alternatives": [benign[item] for item in benign_ids],
        "unknowns": all_unknowns, "recommended_actions": recommendations,
    }
    result["_analysis"] = {
        "claim_verification": verification_options[verification_id],
        "next_check": next_checks.get(next_check_id),
    }
    return result


def _expand_claim(case: InvestigationCase, option: Mapping[str, Any]) -> dict[str, Any]:
    evidence_id = option["evidence_ids"][0]
    record = next(item.record for item in case.evidence if item.evidence_id == evidence_id)
    event = _eventdata(record)
    kind = option["claim_type"]
    if kind == "encoded_powershell":
        return {"claim_type": kind, "evidence_ids": [evidence_id], "subject": None, "object": None}
    if kind == "authentication_window":
        return {"claim_type": kind, "evidence_ids": [evidence_id], "subject": event.get("targetUserName") or event.get("user"), "object": event.get("ipAddress") or event.get("sourceIp")}
    return {"claim_type": kind, "evidence_ids": [evidence_id], "subject": event.get("processGuid"), "object": event.get("parentProcessGuid")}


def _add_authentication_cards(items: list[Any], facts: list[dict[str, str]], claims: list[dict[str, Any]], benign: list[dict[str, str]], unknowns: list[dict[str, str]]) -> None:
    """Add generic Windows authentication cards from observed event fields."""
    event_ids = {str(_system(item.record).get("eventID", "")) for item in items}
    users = sorted({str(_eventdata(item.record).get("targetUserName") or _eventdata(item.record).get("user")) for item in items if _eventdata(item.record).get("targetUserName") or _eventdata(item.record).get("user")})
    logon_types = sorted({str(_eventdata(item.record).get("logonType")) for item in items if _eventdata(item.record).get("logonType")})
    if users:
        facts.append({"id": f"F{len(facts)+1:02d}", "evidence_id": items[0].evidence_id, "text": f"Authentication evidence for account {', '.join(users)}: Windows event IDs {', '.join(sorted(event_ids)) or 'unknown'}; logon types {', '.join(logon_types) or 'not recorded'}."})
    for item in items:
        event = _eventdata(item.record)
        if (event.get("targetUserName") or event.get("user")) and (event.get("ipAddress") or event.get("sourceIp")):
            claims.append({"id": f"C{len(claims)+1:02d}", "claim_type": "authentication_window", "evidence_ids": [item.evidence_id]})
            break
    ips = {str(_eventdata(item.record).get("ipAddress") or _eventdata(item.record).get("sourceIp")) for item in items if _eventdata(item.record).get("ipAddress") or _eventdata(item.record).get("sourceIp")}
    if ips and ips.issubset({"127.0.0.1", "::1", "-"}):
        benign.append({"id": "B02", "text": "The observed source is local/loopback, which may be consistent with an interactive or local service logon; authorization context was not collected."})
        unknowns.append({"id": "U04", "text": "No external source address was observed in the collected authentication events."})
    if "4625" not in event_ids:
        unknowns.append({"id": "U05", "text": "No failed logon event was returned in the scoped authentication evidence."})


def _add_sysmon_seed_fact(evidence_id: str, event: Mapping[str, Any], system: Mapping[str, Any], facts: list[dict[str, str]]) -> None:
    """Render only the current profile contract's dossier fields.

    The raw archive can contain dozens of fields. This summary is the sole
    seed-event view supplied to the assessor; process GUIDs and raw-only
    fields remain available for collection/audit but never enter this text.
    """
    event_id = str(system.get("eventID", ""))
    contract = contract_for_event_id(event_id)
    if contract is None:
        return
    values = contract.values(event)
    # Base64 command text is decoded separately and must never become prompt
    # ballast in the general process profile summary.
    if event_id == "1":
        values.pop("command_line", None)
    rendered = [
        f"{name.replace('_', ' ')}={_safe_text(value, 160, 'not recorded')}"
        for name, value in values.items() if value not in (None, "")
    ]
    if rendered:
        label = contract.profile_id.removeprefix("windows_sysmon_").replace("_", " ")
        facts.append({"id": f"F{len(facts)+1:02d}", "evidence_id": evidence_id, "text": f"Observed Sysmon Event ID {event_id} ({label}): " + "; ".join(rendered[:7]) + "."})


def _action(action: str, evidence_ids: list[str], case: InvestigationCase) -> dict[str, Any]:
    is_authentication = bool(case.evidence and case.evidence[0].event_type == "authentication")
    templates = {
        "preserve_evidence": (("Preserve the cited authentication events and account context before they expire." if is_authentication else "Preserve the cited telemetry and relevant process context before they expire."), "Collection may consume analyst time and storage."),
        "validate_change": ("Validate whether the observed activity was authorized.", "A delayed validation may postpone a response decision."),
    }
    reason, risk = templates[action]
    return {"action": action, "reason": reason, "risk": risk, "evidence_ids": evidence_ids}


def _eventdata(record: Mapping[str, Any]) -> Mapping[str, Any]:
    event = record.get("event", {}) if isinstance(record.get("event"), Mapping) else {}
    data = event.get("data", {}) if isinstance(event.get("data"), Mapping) else {}
    win = data.get("win", {}) if isinstance(data.get("win"), Mapping) else {}
    return win.get("eventdata", {}) if isinstance(win.get("eventdata"), Mapping) else {}


def _system(record: Mapping[str, Any]) -> Mapping[str, Any]:
    event = record.get("event", {}) if isinstance(record.get("event"), Mapping) else {}
    data = event.get("data", {}) if isinstance(event.get("data"), Mapping) else {}
    win = data.get("win", {}) if isinstance(data.get("win"), Mapping) else {}
    return win.get("system", {}) if isinstance(win.get("system"), Mapping) else {}


def _is_encoded_powershell(event: Mapping[str, Any]) -> bool:
    return "powershell" in str(event.get("image", "")).lower() and "-encodedcommand" in str(event.get("commandLine", "")).lower()


def _direct_parent_summary(case: InvestigationCase) -> tuple[str, str] | None:
    seed = case.evidence[0] if case.evidence else None
    if not seed:
        return None
    parent = _eventdata(seed.record).get("parentProcessGuid")
    for item in case.evidence:
        event = _eventdata(item.record)
        if parent and event.get("processGuid") == parent:
            return item.evidence_id, f"Direct parent process observed: {_safe_text(event.get('image'), 240, 'unknown image')}."
    return None


def _context_summary(case: InvestigationCase) -> str | None:
    names = []
    for item in case.evidence:
        if item.evidence_id in case.contextual_evidence_ids:
            image = _eventdata(item.record).get("image")
            if image:
                names.append(_safe_text(str(image).rsplit("\\", 1)[-1], 128, "unknown"))
    return f"Context only (not causal): nearby same-parent processes: {', '.join(sorted(set(names)))}." if names else None


def _seed_evidence_ids(case: InvestigationCase) -> list[str]:
    return [case.evidence[0].evidence_id] if case.evidence else []


def _known_list(value: Any, options: Mapping[str, Any], name: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value) or not set(value).issubset(options):
        raise ValueError(f"{name} contains an unknown option")


def _dedupe_by_id(items: list[dict[str, str]]) -> list[dict[str, str]]:
    return list({item["id"]: item for item in items}.values())


def _llm_activity_cards(cards: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return model-safe activity cards without correlation implementation IDs.

    Evidence IDs and card IDs remain intact for citation and verification.  A
    process GUID is useful to the collector and the analyst appendix, but it
    is neither required nor appropriate for a selector-only model prompt.
    """
    return [
        {
            "card_id": card["card_id"],
            "kind": card["kind"],
            "evidence_ids": list(card["evidence_ids"]),
            "observed": _llm_observed(card.get("observed", {})),
            "text": card["text"],
        }
        for card in cards
    ]


def _llm_observed(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _llm_observed(item)
            for key, item in value.items()
            if "guid" not in str(key).lower()
        }
    if isinstance(value, list):
        return [_llm_observed(item) for item in value]
    if isinstance(value, str):
        return _safe_text(value, 240, "")
    return value


def _safe_mitre(value: Any) -> dict[str, Any]:
    """Keep only the small Wazuh ATT&CK shape; raw rule metadata is not prompt input."""
    if not isinstance(value, Mapping):
        return {}
    safe: dict[str, Any] = {}
    for key in ("id", "tactic", "technique"):
        item = value.get(key)
        if isinstance(item, list):
            safe[key] = [_safe_text(entry, 96, "") for entry in item[:8] if _safe_text(entry, 96, "")]
        elif item is not None:
            text = _safe_text(item, 96, "")
            if text:
                safe[key] = text
    return safe


def _safe_text(value: Any, limit: int, fallback: str | None) -> str | None:
    """Bound prompt values and neutralize control characters from raw telemetry."""
    if value is None:
        return fallback
    text = " ".join(str(value).replace("\x00", " ").split())
    if not text:
        return fallback
    return text if len(text) <= limit else text[:limit] + "…[truncated]"
