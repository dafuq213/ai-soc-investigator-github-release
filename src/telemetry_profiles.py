"""Deterministic telemetry-profile routing and bounded Sysmon collection.

Profiles describe evidence mechanics, not detections or threat verdicts.  They
are selected from observed Wazuh seed fields; an LLM neither selects a profile
nor supplies a query value.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

try:
    from .case_models import InvestigationCase
    from .sysmon_profile_contracts import PROFILE_BY_EVENT_ID, contract_for_event_id
except ImportError:
    from case_models import InvestigationCase
    from sysmon_profile_contracts import PROFILE_BY_EVENT_ID, contract_for_event_id


# Compatibility alias for existing callers. New code should use the profile
# contract rather than its own Event-ID mapping.
_PROFILE_BY_EVENT_ID = PROFILE_BY_EVENT_ID
_PROCESS_ACTIVITY_EVENTS = ("3", "7", "11", "12", "13", "14", "22")


def select_telemetry_profiles(case: InvestigationCase) -> list[str]:
    """Return profile IDs supported by the observed seed; never infer one."""
    seed = case.evidence[0].record if case.evidence else {}
    if not _is_sysmon(seed):
        return []
    event_id = _event_id(seed)
    profile = _PROFILE_BY_EVENT_ID.get(event_id)
    return [profile] if profile else []


class SysmonProfileCollector:
    """Collect only exact, profile-defined evidence from the controlled tool layer."""
    MAX_RELATED_RECORDS = 8

    def __init__(self, tools: Any):
        self.tools = tools
        self._collection_limit = 5

    def collect(self, case: InvestigationCase, hours: int = 24, limit: int = 5) -> InvestigationCase:
        self._collection_limit = limit
        profiles = select_telemetry_profiles(case)
        case.correlations["telemetry_profiles"] = [{"profile_id": item, "status": "selected"} for item in profiles]
        if not profiles:
            return case
        seed = case.evidence[0].record
        fields = _eventdata(seed)
        agent_id = seed.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            case.correlations["telemetry_profiles"][0]["status"] = "unavailable_missing_agent_id"
            return case
        window = _seed_window(seed.get("timestamp"), hours)
        if window is None:
            case.correlations["telemetry_profiles"][0]["status"] = "unavailable_missing_or_invalid_timestamp"
            return case
        event_id = _event_id(seed)
        contract = contract_for_event_id(event_id)
        if contract is None:
            return case
        missing = list(contract.missing_required(fields))
        # A Sysmon all-zero GUID is a sentinel, not an observed actor. Treat
        # it as unavailable even though the field is technically populated.
        for key, value in contract.key_values(fields).items():
            if key.endswith("process_guid") and not _text(value) and key not in missing:
                missing.append(key)
        if missing:
            case.correlations["telemetry_profiles"][0]["status"] = "unavailable_missing_" + "_or_".join(missing)
            return case
        if event_id == "10":
            self._process_access(case, fields, agent_id, window, limit)
        else:
            process_guid = _text(contract.key_values(fields).get("process_guid"))
            # Any event with an actor ProcessGuid gets the same bounded actor
            # context. A registry, DNS, or network seed must not lose related
            # same-process evidence merely because it was not Event ID 1.
            self._actor_context(case, process_guid, fields, agent_id, window, limit, include_activity=True)
        return case

    def _process_access(self, case: InvestigationCase, fields: Mapping[str, Any], agent_id: str, window: tuple[str, str], limit: int) -> None:
        contract = contract_for_event_id("10")
        values = contract.key_values(fields) if contract else {}
        source_guid = _text(values.get("source_process_guid"))
        target_guid = _text(values.get("target_process_guid"))
        if not source_guid or not target_guid:
            case.correlations["telemetry_profiles"][0]["status"] = "unavailable_missing_source_or_target_process_guid"
            return
        self._add(case, "get_sysmon_profile_events", {"process_guid": source_guid, "agent_id": agent_id, "start_time": window[0], "end_time": window[1], "event_ids": ["1"], "relationship": "actor"})
        self._add(case, "get_sysmon_profile_events", {"process_guid": target_guid, "agent_id": agent_id, "start_time": window[0], "end_time": window[1], "event_ids": ["1"], "relationship": "actor"})

    def _actor_context(self, case: InvestigationCase, process_guid: str, fields: Mapping[str, Any], agent_id: str, window: tuple[str, str], limit: int, include_activity: bool) -> None:
        parent_guid = _text(fields.get("parentProcessGuid"))
        if parent_guid:
            self._add(case, "get_sysmon_profile_events", {"process_guid": parent_guid, "agent_id": agent_id, "start_time": window[0], "end_time": window[1], "event_ids": ["1"], "relationship": "actor"})
        children = self._add(case, "get_sysmon_profile_events", {"process_guid": process_guid, "agent_id": agent_id, "start_time": window[0], "end_time": window[1], "event_ids": ["1"], "relationship": "child"})
        if include_activity:
            self._add(case, "get_sysmon_profile_events", {"process_guid": process_guid, "agent_id": agent_id, "start_time": window[0], "end_time": window[1], "event_ids": list(_PROCESS_ACTIVITY_EVENTS), "relationship": "actor"})
            self._add(case, "get_sysmon_profile_events", {"process_guid": process_guid, "agent_id": agent_id, "start_time": window[0], "end_time": window[1], "event_ids": ["10"], "relationship": "access"})
            # One hop only: direct children are proven by ParentProcessGuid,
            # then their event family is proven by their own ProcessGuid. This
            # permits a seed process to be linked to a network-capable child
            # without broad host-wide collection or inferred causality.
            for child_guid in _child_guids(children)[:10]:
                self._add(case, "get_sysmon_profile_events", {"process_guid": child_guid, "agent_id": agent_id, "start_time": window[0], "end_time": window[1], "event_ids": list(_PROCESS_ACTIVITY_EVENTS), "relationship": "actor"})
                self._add(case, "get_sysmon_profile_events", {"process_guid": child_guid, "agent_id": agent_id, "start_time": window[0], "end_time": window[1], "event_ids": ["10"], "relationship": "access"})

    def _add(self, case: InvestigationCase, tool: str, arguments: dict[str, Any]) -> Mapping[str, Any]:
        # Keep every controlled relationship small. The dossier performs a
        # second reduction, but collection itself must not pull 25+ unrelated
        # same-process records merely because the caller selected a lower cap.
        related_records = max(0, len(case.evidence) - 1)
        remaining = self.MAX_RELATED_RECORDS - related_records
        if remaining <= 0:
            result = {"ok": True, "tool": tool, "data": [], "meta": {"source": "telemetry", "index": "wazuh-archives-*", "count": 0, "total": 0, "truncated": True, "skipped": "case_related_record_cap"}, "error": None}
            case.add_tool_result(tool, arguments, result)
            return result
        arguments.setdefault("limit", min(self._collection_limit, remaining))
        result = self.tools.get_sysmon_profile_events(**arguments)
        case.add_tool_result(tool, arguments, result)
        return result


def _is_sysmon(record: Mapping[str, Any]) -> bool:
    system = _system(record)
    provider = str(system.get("providerName", "")).lower()
    groups = record.get("rule", {}).get("groups", []) if isinstance(record.get("rule"), Mapping) else []
    return "sysmon" in provider or any("sysmon" in str(group).lower() for group in groups)


def _seed_window(timestamp: Any, hours: int) -> tuple[str, str] | None:
    if not isinstance(timestamp, str) or not isinstance(hours, int) or not 1 <= hours <= 168:
        return None
    try:
        seed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (
        (seed - timedelta(hours=hours)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        (seed + timedelta(minutes=5)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def _eventdata(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return record.get("event", {}).get("data", {}).get("win", {}).get("eventdata", {}) if isinstance(record.get("event"), Mapping) else {}


def _system(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return record.get("event", {}).get("data", {}).get("win", {}).get("system", {}) if isinstance(record.get("event"), Mapping) else {}


def _event_id(record: Mapping[str, Any]) -> str:
    return str(_system(record).get("eventID", ""))


def _text(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    # Sysmon uses this sentinel when Windows cannot attribute a connection to
    # a process. It is not a usable correlation key.
    if text.strip("{}").replace("-", "") == "0" * 32:
        return None
    return text


def _first(values: Mapping[str, Any], *keys: str) -> Any:
    return next((values[key] for key in keys if values.get(key) not in (None, "")), None)


def _child_guids(result: Mapping[str, Any]) -> list[str]:
    """Extract only directly observed child process GUIDs from a tool result."""
    values: set[str] = set()
    for record in result.get("data", []) if isinstance(result.get("data"), list) else []:
        if not isinstance(record, Mapping):
            continue
        value = _text(_eventdata(record).get("processGuid"))
        if value:
            values.add(value)
    return sorted(values)
