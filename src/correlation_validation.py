"""Evidence-key validation for controlled entity-correlation results."""
from __future__ import annotations

from typing import Any, Mapping


def validate_collection_execution(execution: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Confirm every returned record still contains the exact queried entity."""
    checks: list[dict[str, Any]] = []
    for action in execution.get("executed_actions", []) if isinstance(execution.get("executed_actions"), list) else []:
        if not isinstance(action, Mapping):
            continue
        for item in action.get("executions", []) if isinstance(action.get("executions"), list) else []:
            if not isinstance(item, Mapping):
                continue
            arguments, result = item.get("arguments"), item.get("result")
            if not isinstance(arguments, Mapping) or not isinstance(result, Mapping):
                continue
            records = result.get("data", []) if isinstance(result.get("data"), list) else []
            if item.get("tool") == "get_entity_activity":
                entity_type, value = arguments.get("entity_type"), arguments.get("value")
                matching = lambda record: record_matches_entity(record, entity_type, value)
            elif item.get("tool") == "get_authentication_activity":
                entity_type, value = "authentication", arguments.get("user") or arguments.get("source_ip")
                matching = lambda record: record_matches_authentication(record, arguments.get("user"), arguments.get("source_ip"))
            else:
                continue
            invalid = [_record_id(record) for record in records if isinstance(record, Mapping) and not matching(record)]
            checks.append({
                "action_id": action.get("action_id"), "entity_type": entity_type, "value": value,
                "returned": len(records), "matched": len(records) - len(invalid), "invalid_record_ids": invalid,
                "passed": not invalid,
            })
    return checks


def record_matches_authentication(record: Mapping[str, Any], user: Any, source_ip: Any) -> bool:
    """Authentication results must retain every key the query used."""
    fields = _eventdata(record)
    lowered = {str(key).casefold(): item for key, item in fields.items()}
    user_matches = not isinstance(user, str) or any(str(lowered.get(key, "")) == user for key in ("targetusername", "user", "subjectusername"))
    ip_matches = not isinstance(source_ip, str) or any(str(lowered.get(key, "")) == source_ip for key in ("ipaddress", "sourceip"))
    return user_matches and ip_matches


def record_matches_entity(record: Mapping[str, Any], entity_type: Any, value: Any) -> bool:
    if not isinstance(entity_type, str) or not isinstance(value, str):
        return False
    fields = _eventdata(record)
    values = {str(key).casefold(): item for key, item in fields.items()}
    aliases = {
        "process_guid": ("processguid", "sourceprocessguid", "targetprocessguid"),
        "parent_process_guid": ("parentprocessguid",),
        "registry_key": ("targetobject",),
        "file_path": ("targetfilename", "imageloaded"),
        "ip": ("destinationip", "sourceip", "ipaddress"),
        "domain": ("queryname", "destinationhostname"),
    }
    if entity_type == "hash":
        return any(value.casefold() in str(item).casefold() for key, item in values.items() if key == "hashes") or _nested_contains(record, value)
    if entity_type not in aliases:
        return False
    return any(str(values.get(alias, "")) == value for alias in aliases[entity_type]) or _nested_exact(record, entity_type, value)


def concise_record_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    fields = _eventdata(record)
    system = _mapping_path(record, "event", "data", "win", "system")
    return {
        "alert_id": _record_id(record), "timestamp": record.get("timestamp"), "event_id": _field(system, "eventID"),
        "image": _field(fields, "image", "sourceImage", "targetImage"),
        "parent_image": _field(fields, "parentImage"), "target": _field(fields, "targetObject", "targetFilename", "destinationIp", "queryName"),
    }


def _eventdata(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping_path(record, "event", "data", "win", "eventdata")


def _mapping_path(value: Mapping[str, Any], *path: str) -> Mapping[str, Any]:
    current: Any = value
    for key in path:
        current = current.get(key) if isinstance(current, Mapping) else None
    return current if isinstance(current, Mapping) else {}


def _field(value: Mapping[str, Any], *names: str) -> Any:
    lowered = {str(key).casefold(): item for key, item in value.items()}
    return next((lowered[name.casefold()] for name in names if lowered.get(name.casefold()) not in (None, "")), None)


def _record_id(record: Mapping[str, Any]) -> Any:
    return record.get("wazuh_alert_id") or record.get("alert_id")


def _nested_exact(record: Mapping[str, Any], entity_type: str, value: str) -> bool:
    paths = {"file_path": (("event", "file", "path"),), "ip": (("event", "source", "ip"), ("event", "destination", "ip")), "domain": (("event", "dns", "question", "name"), ("event", "url", "domain"))}
    for path in paths.get(entity_type, ()):
        current: Any = record
        for key in path:
            current = current.get(key) if isinstance(current, Mapping) else None
        if current == value:
            return True
    return False


def _nested_contains(record: Mapping[str, Any], value: str) -> bool:
    def walk(item: Any) -> bool:
        if isinstance(item, Mapping):
            return any(walk(child) for child in item.values())
        if isinstance(item, list):
            return any(walk(child) for child in item)
        return isinstance(item, str) and value.casefold() in item.casefold()
    return walk(record)
