"""Execute an entity collection plan through controlled Wazuh tool methods."""
from __future__ import annotations

from typing import Any, Mapping


MAX_RELATED_RECORDS = 12
MAX_PER_QUERY = 5


def execute_entity_collection(tools: Any, plan: Mapping[str, Any]) -> dict[str, Any]:
    """Run only preplanned actions and return traceable, bounded tool results."""
    actions = plan.get("actions", [])
    if not isinstance(actions, list):
        raise ValueError("collection plan actions must be a list")
    remaining = MAX_RELATED_RECORDS
    seen_records: set[str] = set()
    executed: list[dict[str, Any]] = []
    limitations = list(plan.get("limitations", [])) if isinstance(plan.get("limitations"), list) else []
    for action in actions:
        if remaining <= 0:
            limitations.append("Related-evidence collection cap reached.")
            break
        if not isinstance(action, Mapping):
            continue
        action_results = _deduplicate_results(_execute_action(tools, action, remaining), seen_records)
        executed.append({"action_id": action.get("id"), "kind": action.get("kind"), "reason": action.get("reason"), "executions": action_results})
        remaining -= sum(len(item.get("result", {}).get("data", [])) for item in action_results if isinstance(item.get("result"), Mapping))
    return {"executed_actions": executed, "limitations": limitations, "related_record_cap": MAX_RELATED_RECORDS}


def _execute_action(tools: Any, action: Mapping[str, Any], remaining: int) -> list[dict[str, Any]]:
    kind, arguments = action.get("kind"), action.get("arguments")
    if not isinstance(kind, str) or not isinstance(arguments, Mapping):
        return [{"tool": "not_executed", "arguments": {}, "result": _skipped("invalid_action")}]
    scope = {key: arguments[key] for key in ("agent_id", "host", "start_time", "end_time") if arguments.get(key)}
    limit = min(MAX_PER_QUERY, remaining)

    def entity(entity_type: str, value: str) -> dict[str, Any]:
        call_args = {"entity_type": entity_type, "value": value, **scope, "limit": limit}
        return {"tool": "get_entity_activity", "arguments": call_args, "result": tools.get_entity_activity(**call_args)}

    def process_creation(value: str) -> dict[str, Any] | None:
        """Prefer the exact process-creation record when Sysmon context exists.

        A ProcessGuid can also occur on process termination, image-load, or
        access events.  Those records are useful follow-up telemetry, but they
        cannot establish how the process began.  This narrow lookup is only
        used when the plan has an observed agent and timestamp window; callers
        without Sysmon data retain the generic entity-query fallback below.
        """
        method = getattr(tools, "get_sysmon_profile_events", None)
        if not callable(method) or not isinstance(scope.get("agent_id"), str) or not scope.get("start_time") or not scope.get("end_time"):
            return None
        call_args = {
            "process_guid": value,
            "agent_id": scope["agent_id"],
            "start_time": scope["start_time"],
            "end_time": scope["end_time"],
            "event_ids": ["1"],
            "relationship": "actor",
            "limit": limit,
        }
        return {"tool": "get_sysmon_profile_events", "arguments": call_args, "result": method(**call_args)}

    def preferred_process(value: str) -> list[dict[str, Any]]:
        creation = process_creation(value)
        if creation is not None and isinstance(creation.get("result"), Mapping) and creation["result"].get("data"):
            return [creation]
        fallback = entity("process_guid", value)
        return [creation, fallback] if creation is not None else [fallback]

    if kind == "process_lineage":
        value = arguments.get("process_guid")
        if isinstance(value, str):
            actor_items = preferred_process(value)
            actor = actor_items[-1] if len(actor_items) == 1 else actor_items[0]
            consumed = sum(len(item["result"].get("data", [])) for item in actor_items if isinstance(item.get("result"), Mapping))
            child_limit = min(MAX_PER_QUERY, max(0, remaining - consumed))
            if child_limit <= 0:
                return [*actor_items, {"tool": "get_entity_activity", "arguments": {}, "result": _skipped("related_record_cap")}]
            child_args = {"entity_type": "parent_process_guid", "value": value, **scope, "limit": child_limit}
            child = {"tool": "get_entity_activity", "arguments": child_args, "result": tools.get_entity_activity(**child_args)}
            return [*actor_items, child]
    if kind in {"parent_process_origin", "target_process_origin"}:
        value = arguments.get("process_guid")
        if isinstance(value, str):
            return preferred_process(value)
    values = {
        "exact_registry_key": ("registry_key", "registry_key"),
        "exact_file_path": ("file_path", "file_path"),
        "exact_hash": ("hash", "hash_value"),
        "same_host_ip": ("ip", "ip"),
        "same_host_domain": ("domain", "domain"),
    }
    if kind in values:
        entity_type, key = values[kind]
        value = arguments.get(key)
        if isinstance(value, str):
            return [entity(entity_type, value)]
    if kind == "authentication_context":
        if not isinstance(arguments.get("agent_id"), str):
            return [{"tool": "get_authentication_activity", "arguments": {}, "result": _skipped("authentication_context_requires_agent_id")}]
        call_args = {key: arguments[key] for key in ("user", "source_ip", "agent_id", "start_time", "end_time") if arguments.get(key)}
        call_args["limit"] = limit
        return [{"tool": "get_authentication_activity", "arguments": call_args, "result": tools.get_authentication_activity(**call_args)}]
    return [{"tool": "not_executed", "arguments": {}, "result": _skipped("unsupported_action_kind")}]


def _skipped(reason: str) -> dict[str, Any]:
    return {"ok": True, "tool": "not_executed", "data": [], "meta": {"count": 0, "skipped": reason}, "error": None}


def _deduplicate_results(executions: list[dict[str, Any]], seen: set[str]) -> list[dict[str, Any]]:
    """Keep one copy of each source event even when several keys find it."""
    for item in executions:
        result = item.get("result")
        if not isinstance(result, Mapping) or not isinstance(result.get("data"), list):
            continue
        unique = []
        for record in result["data"]:
            if not isinstance(record, Mapping):
                continue
            identity = _record_identity(record)
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(record)
        item["result"] = {**result, "data": unique, "meta": {**(result.get("meta") if isinstance(result.get("meta"), Mapping) else {}), "count": len(unique)}}
    return executions


def _record_identity(record: Mapping[str, Any]) -> str:
    event = record.get("event") if isinstance(record.get("event"), Mapping) else {}
    data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
    win = data.get("win") if isinstance(data.get("win"), Mapping) else {}
    system = win.get("system") if isinstance(win.get("system"), Mapping) else {}
    event_record_id = system.get("eventRecordID")
    agent_id = record.get("agent_id")
    if event_record_id not in (None, "") and agent_id not in (None, ""):
        return f"event:{agent_id}:{event_record_id}"
    return f"document:{record.get('alert_id')}"

