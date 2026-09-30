"""Deterministic, entity-based correlation planning for normalized alerts.

The planner has no Wazuh query access and no threat logic. It emits only a
small set of safe collection intents whose values came from the normalized
seed alert. A later executor maps these intents to controlled tool methods.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


MAX_ACTIONS = 8


def plan_entity_collection(alert: Mapping[str, Any], window_minutes: int = 30) -> dict[str, Any]:
    """Return a bounded, deduplicated correlation plan for one normalized alert."""
    if not 5 <= window_minutes <= 24 * 60:
        raise ValueError("window_minutes must be from 5 to 1440")
    entities = alert.get("entities")
    if not isinstance(entities, Mapping):
        raise ValueError("normalized alert must contain entities")
    window = _seed_window(alert.get("timestamp_utc"), window_minutes)
    scope = _scope(entities)
    limitations: list[str] = []
    if window is None:
        limitations.append("Seed timestamp is unavailable or invalid; no time-bounded correlation was planned.")
    if scope is None:
        limitations.append("Host or agent identity is unavailable; no host-scoped correlation was planned.")
    if window is None or scope is None:
        return {"actions": [], "limitations": limitations}

    actions: list[dict[str, Any]] = []

    def add(kind: str, reason: str, **arguments: Any) -> None:
        candidate = {"kind": kind, "reason": reason, "arguments": {**scope, **window, **arguments}}
        key = (kind, tuple(sorted((name, str(value)) for name, value in candidate["arguments"].items())))
        if len(actions) < MAX_ACTIONS and not any(item["_key"] == key for item in actions):
            candidate["_key"] = key
            actions.append(candidate)

    process_guid = _text(entities.get("process_guid"))
    parent_guid = _text(entities.get("parent_process_guid"))
    target_guid = _text(entities.get("target_process_guid"))
    if process_guid:
        add("process_lineage", "Exact observed process GUID", process_guid=process_guid)
    if parent_guid:
        add("parent_process_origin", "Exact observed parent process GUID", process_guid=parent_guid)
    if target_guid:
        add("target_process_origin", "Exact observed target process GUID", process_guid=target_guid)

    registry_key = _text(entities.get("registry_key"))
    if registry_key:
        add("exact_registry_key", "Exact observed registry key", registry_key=registry_key)
    file_path = _text(entities.get("file_path"))
    if file_path:
        add("exact_file_path", "Exact observed file path", file_path=file_path)
    # Exact process lineage is a stronger relationship than a binary hash.
    # When a process GUID is available, same-hash activity often expands into
    # unrelated executions of common binaries (cmd.exe, browsers, etc.) and
    # consumes the bounded evidence budget.  Retain hash collection as a
    # fallback for alerts without process topology, where it can still provide
    # a useful exact pivot without asserting any causal link.
    if not process_guid and not parent_guid:
        for hash_value in _texts(entities.get("file_hashes"))[:2]:
            add("exact_hash", "Exact observed file hash", hash_value=hash_value)
    for ip in (_text(entities.get("source_ip")), _text(entities.get("destination_ip"))):
        if ip:
            add("same_host_ip", "Exact observed IP address", ip=ip)
    domain = _text(entities.get("domain"))
    if domain:
        add("same_host_domain", "Exact observed domain", domain=domain)

    # User-only searches are intentionally avoided for process/file alerts:
    # they are often noisy. Authentication context is relevant only when the
    # seed is an identity event or it includes the specific source IP.
    user = _text(entities.get("user"))
    source = alert.get("source") if isinstance(alert.get("source"), Mapping) else {}
    groups = source.get("groups") if isinstance(source.get("groups"), list) else []
    identity_context = bool(_text(entities.get("source_ip"))) or str(source.get("channel", "")).casefold() == "security" or any("authentication" in str(group).casefold() for group in groups)
    if user and identity_context:
        arguments: dict[str, Any] = {"user": user}
        if _text(entities.get("source_ip")):
            arguments["source_ip"] = _text(entities.get("source_ip"))
        add("authentication_context", "Observed identity with authentication-relevant context", **arguments)

    for index, action in enumerate(actions, start=1):
        action["id"] = f"C{index:02d}"
        action.pop("_key", None)
    if not actions:
        limitations.append("The alert has no supported correlation entity; preserve the seed alert without broad searching.")
    return {"actions": actions, "limitations": limitations}


def _scope(entities: Mapping[str, Any]) -> dict[str, str] | None:
    agent_id, host = _text(entities.get("agent_id")), _text(entities.get("host"))
    if agent_id:
        return {"agent_id": agent_id}
    if host:
        return {"host": host}
    return None


def _seed_window(value: Any, minutes: int) -> dict[str, str] | None:
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Normalized producer timestamps may be explicitly UTC by field semantics
    # (for example, Sysmon UtcTime) while omitting an offset suffix. Never let
    # the investigator host's local timezone shift the correlation window.
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)
    return {
        "start_time": (timestamp - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
        "end_time": (timestamp + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
    }


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _texts(value: Any) -> list[str]:
    return [item.strip() for item in value if isinstance(item, str) and item.strip()] if isinstance(value, list) else []
