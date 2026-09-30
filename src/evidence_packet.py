"""Build a compact, source-traceable packet for a later LLM assessment.

The packet is intentionally event-family neutral.  It accepts a normalized
Wazuh alert and the output of the entity collection executor; it does not
decide whether activity is benign or malicious, nor does it select a Sysmon
profile.  Correlation identifiers remain implementation details while the
packet presents readable process, user, target, and network context.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Any, Mapping


MAX_EVIDENCE_ITEMS = 13  # seed plus at most the executor's 12 related events
MAX_COMMAND_LINE_CHARS = 500
DISPLAY_ENTITY_KEYS = (
    "host", "user", "process_name", "process_path", "parent_process_name",
    "parent_process_path", "command_line", "source_ip", "destination_ip",
    "destination_port", "domain", "file_path", "registry_key",
    "registry_value", "target_process_name", "service_name", "service_image_path",
    "service_account", "service_start_type", "service_type", "vulnerability_cve",
    "vulnerability_package", "vulnerability_package_version",
    "vulnerability_severity", "vulnerability_cvss",
)
ENCODED_POWERSHELL = re.compile(r"(?:^|\s)-(?:encodedcommand|enc)\s+(?:['\"])?(?P<payload>[A-Za-z0-9+/=_-]+)", re.IGNORECASE)


def build_evidence_packet(normalized_alert: Mapping[str, Any], execution: Mapping[str, Any]) -> dict[str, Any]:
    """Return a bounded assessment input composed exclusively of collected data.

    The first item is always the alert itself.  Related records are retained
    only once, are labelled with the collection action that found them, and
    never include raw event payloads such as call traces.
    """
    entities = _mapping(normalized_alert.get("entities"))
    source = _mapping(normalized_alert.get("source"))
    seed_id = _string(normalized_alert.get("alert_id"))
    evidence = [_seed_item(normalized_alert)]
    seen = {_record_identity_from_reference(normalized_alert)}
    seed_semantic_identity = _semantic_identity_from_alert(normalized_alert)

    for action in _list(execution.get("executed_actions")):
        if len(evidence) >= MAX_EVIDENCE_ITEMS or not isinstance(action, Mapping):
            break
        for item in _list(action.get("executions")):
            result = _mapping(item.get("result")) if isinstance(item, Mapping) else {}
            for record in _list(result.get("data")):
                if len(evidence) >= MAX_EVIDENCE_ITEMS:
                    break
                if not isinstance(record, Mapping):
                    continue
                identity = _record_identity(record)
                if identity in seen or _is_seed_record(record, normalized_alert):
                    continue
                # An alert-index document and its archive-index copy normally
                # have different OpenSearch IDs.  Collapse them only when an
                # exact, strong event identity matches; retain both references.
                record_semantic_identity = _semantic_identity_from_record(record)
                if seed_semantic_identity and record_semantic_identity == seed_semantic_identity:
                    _append_source(evidence[0], record)
                    seen.add(identity)
                    continue
                seen.add(identity)
                evidence.append(_related_item(record, action, item))

    evidence = [evidence[0], *_coalesce_related(evidence[1:])]
    for index, item in enumerate(evidence, start=1):
        item["id"] = f"E{index:02d}"

    return {
        "schema_version": "evidence_packet_v1",
        "alert": {
            "alert_id": seed_id,
            "timestamp_utc": _string(normalized_alert.get("timestamp_utc")),
            "title": _string(normalized_alert.get("title")),
            "rule_id": _string(normalized_alert.get("rule_id")),
            "severity": normalized_alert.get("severity") if isinstance(normalized_alert.get("severity"), int) else None,
            "source": {
                key: source.get(key)
                for key in ("channel", "event_id", "provider", "groups", "mitre")
                if source.get(key) not in (None, "", [], {})
            },
        },
        "observed_entities": {key: _display_value(key, entities.get(key)) for key in DISPLAY_ENTITY_KEYS if _display_value(key, entities.get(key)) is not None},
        "evidence": evidence,
        "collection": {
            "actions_executed": [
                {"id": _string(action.get("action_id")), "kind": _string(action.get("kind")), "reason": _string(action.get("reason"))}
                for action in _list(execution.get("executed_actions")) if isinstance(action, Mapping)
            ],
            "limitations": _strings(execution.get("limitations")),
            "related_record_cap": execution.get("related_record_cap"),
        },
    }


def _seed_item(alert: Mapping[str, Any]) -> dict[str, Any]:
    entities = _mapping(alert.get("entities"))
    source = _mapping(alert.get("source"))
    fields = _readable_fields(entities)
    source_reference = {"alert_id": _string(alert.get("alert_id")), "document_id": _string(_mapping(alert.get("raw_reference")).get("document_id"))}
    return {
        "id": "",
        "relationship": "seed_alert",
        "source": source_reference,
        "sources": [source_reference.copy()],
        "timestamp_utc": _string(alert.get("timestamp_utc")),
        "summary": _summary(source.get("event_id"), fields),
        "fields": fields,
    }


def _related_item(record: Mapping[str, Any], action: Mapping[str, Any], execution: Any) -> dict[str, Any]:
    fields = _readable_fields(_record_entities(record))
    event_id = _event_id(record)
    return {
        "id": "",  # assigned after construction for stable contiguous identifiers
        "relationship": _relationship(action, execution),
        "source": {"alert_id": _string(_alert_id(record)), "document_id": _string(record.get("alert_id") or record.get("_id"))},
        "sources": [{"alert_id": _string(_alert_id(record)), "document_id": _string(record.get("alert_id") or record.get("_id"))}],
        "timestamp_utc": _record_timestamp(record),
        "summary": _summary(event_id, fields),
        "fields": fields,
    }


def _coalesce_related(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group repeated, identical observations while retaining every source reference."""
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        key = (str(item.get("relationship")), repr(item.get("fields")))
        current = grouped.get(key)
        if current is None:
            grouped[key] = item
            continue
        current["sources"].extend(item.get("sources", []))
        current["occurrence_count"] = len(current["sources"])
        timestamps = [value for value in (current.get("timestamp_utc"), item.get("timestamp_utc")) if isinstance(value, str)]
        if timestamps:
            current["first_seen_utc"] = min(timestamps)
            current["last_seen_utc"] = max(timestamps)
    return list(grouped.values())


def _relationship(action: Mapping[str, Any], execution: Any) -> str:
    kind = _string(action.get("kind")) or "related_activity"
    arguments = _mapping(execution.get("arguments")) if isinstance(execution, Mapping) else {}
    entity_type = _string(arguments.get("entity_type"))
    if kind == "process_lineage" and entity_type == "parent_process_guid":
        return "direct_child_process"
    return {
        "process_lineage": "same_process",
        "parent_process_origin": "parent_process_origin",
        "target_process_origin": "target_process_origin",
        "exact_registry_key": "same_registry_key",
        "exact_file_path": "same_file_path",
        "exact_hash": "same_hash",
        "same_host_ip": "same_ip",
        "same_host_domain": "same_domain",
        "authentication_context": "authentication_context",
    }.get(kind, "related_activity")


def _record_entities(record: Mapping[str, Any]) -> dict[str, Any]:
    data = _mapping_path(record, "event", "data", "win", "eventdata")
    event = _mapping(record.get("event"))
    return {
        "host": _first(record.get("host"), _mapping(record.get("agent")).get("name"), _mapping(event.get("host")).get("name")),
        "user": _field(data, "user", "targetUserName", "subjectUserName", "sourceUser", "targetUser"),
        "process_name": _field(data, "image", "sourceImage", "targetImage"),
        "process_path": _field(data, "image", "sourceImage", "targetImage"),
        "parent_process_name": _field(data, "parentImage"),
        "parent_process_path": _field(data, "parentImage"),
        "command_line": _field(data, "commandLine", "sourceCommandLine"),
        "source_ip": _field(data, "sourceIp", "ipAddress"),
        "destination_ip": _field(data, "destinationIp"),
        "destination_port": _field(data, "destinationPort"),
        "domain": _field(data, "destinationHostname", "queryName"),
        "file_path": _field(data, "targetFilename", "imageLoaded", "newName"),
        "registry_key": _field(data, "targetObject"),
        "registry_value": _field(data, "details"),
        "target_process_name": _field(data, "targetImage"),
        "service_name": _field(data, "serviceName"),
        "service_image_path": _field(data, "imagePath", "serviceFileName"),
        "service_account": _field(data, "accountName", "serviceAccount"),
        "service_start_type": _field(data, "startType", "serviceStartType"),
        "service_type": _field(data, "serviceType"),
    }


def _readable_fields(entities: Mapping[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in DISPLAY_ENTITY_KEYS:
        value = _display_value(key, entities.get(key))
        if value is not None:
            fields[key] = value
    # Decode the original observed value before the display copy is truncated.
    decoded = _decode_powershell_command(entities.get("command_line"))
    if decoded:
        fields["decoded_command"] = decoded
    return fields


def _decode_powershell_command(command_line: Any) -> str | None:
    """Decode a visible PowerShell ``-EncodedCommand`` value without execution.

    PowerShell commonly encodes these payloads as UTF-16LE, which contains NUL
    bytes at the byte level. Decoding as UTF-16LE converts those bytes into
    ordinary text; malformed, binary, or oversized values are left untouched.
    """
    if not isinstance(command_line, str):
        return None
    match = ENCODED_POWERSHELL.search(command_line)
    if not match:
        return None
    token = match.group("payload").replace("-", "+").replace("_", "/")
    token += "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(token, validate=True)
    except (ValueError, UnicodeError):
        return None
    candidates = []
    if len(raw) >= 2 and raw[1::2].count(0) >= max(1, len(raw) // 4):
        candidates.append("utf-16-le")
    candidates.extend(["utf-8", "utf-16-le"])
    for encoding in candidates:
        try:
            decoded = raw.decode(encoding).replace("\x00", "").strip()
        except UnicodeDecodeError:
            continue
        if decoded and _mostly_printable(decoded):
            return decoded[:MAX_COMMAND_LINE_CHARS] + ("…[truncated]" if len(decoded) > MAX_COMMAND_LINE_CHARS else "")
    return None


def _mostly_printable(value: str) -> bool:
    return sum(character.isprintable() or character in "\r\n\t" for character in value) / len(value) >= 0.95 if value else False


def _summary(event_id: Any, fields: Mapping[str, Any]) -> str:
    parts = []
    if event_id not in (None, ""):
        parts.append(f"Event {event_id}")
    process = fields.get("process_name") or fields.get("target_process_name")
    if process:
        parts.append(f"process {process}")
    target = fields.get("registry_key") or fields.get("file_path") or fields.get("destination_ip") or fields.get("domain") or fields.get("service_name") or fields.get("vulnerability_cve")
    if target:
        parts.append(f"target {target}")
    return "; ".join(parts) if parts else "Observed related event."


def _display_value(key: str, value: Any) -> Any:
    if key == "command_line" and isinstance(value, str):
        return value if len(value) <= MAX_COMMAND_LINE_CHARS else value[:MAX_COMMAND_LINE_CHARS] + "…[truncated]"
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return value if value not in (None, "") else None


def _is_seed_record(record: Mapping[str, Any], alert: Mapping[str, Any]) -> bool:
    """Exclude the source alert even if archive and alerts indexes name IDs differently."""
    reference = _mapping(alert.get("raw_reference"))
    source_ids = {str(item) for item in (alert.get("alert_id"), reference.get("document_id")) if item not in (None, "")}
    record_ids = {str(item) for item in (_alert_id(record), record.get("_id"), record.get("alert_id")) if item not in (None, "")}
    return bool(source_ids.intersection(record_ids))


def _alert_id(record: Mapping[str, Any]) -> Any:
    return record.get("wazuh_alert_id") or record.get("alert_id")


def _record_identity_from_reference(alert: Mapping[str, Any]) -> str:
    reference = _mapping(alert.get("raw_reference"))
    return f"document:{reference.get('document_id') or alert.get('alert_id')}"


def _record_identity(record: Mapping[str, Any]) -> str:
    system = _mapping_path(record, "event", "data", "win", "system")
    event_record_id = system.get("eventRecordID")
    agent_id = record.get("agent_id") or _mapping(record.get("agent")).get("id")
    if event_record_id not in (None, "") and agent_id not in (None, ""):
        return f"event:{agent_id}:{event_record_id}"
    return f"document:{record.get('alert_id') or record.get('_id') or id(record)}"


def _semantic_identity_from_alert(alert: Mapping[str, Any]) -> tuple[str, ...] | None:
    entities = _mapping(alert.get("entities"))
    source = _mapping(alert.get("source"))
    return _strong_semantic_identity(
        host=_first(entities.get("agent_id"), entities.get("host")),
        event_id=source.get("event_id"),
        provider=source.get("provider"),
        channel=source.get("channel"),
        timestamp=alert.get("timestamp_utc"),
        process_guid=_first(entities.get("process_guid"), entities.get("target_process_guid")),
        image=_first(entities.get("process_path"), entities.get("process_name"), entities.get("target_process_name")),
        command_line=entities.get("command_line"),
    )


def _semantic_identity_from_record(record: Mapping[str, Any]) -> tuple[str, ...] | None:
    system = _mapping_path(record, "event", "data", "win", "system")
    data = _mapping_path(record, "event", "data", "win", "eventdata")
    event = _mapping(record.get("event"))
    return _strong_semantic_identity(
        host=_first(record.get("agent_id"), _mapping(record.get("agent")).get("id"), record.get("host"), _mapping(event.get("host")).get("name")),
        event_id=_first(_field(system, "eventID"), event.get("code")),
        provider=_first(_field(system, "providerName"), event.get("provider")),
        channel=_first(_field(system, "channel"), event.get("dataset")),
        timestamp=_first(_field(data, "utcTime"), system.get("systemTime"), record.get("timestamp")),
        process_guid=_first(_field(data, "processGuid", "sourceProcessGuid"), _field(data, "targetProcessGuid")),
        image=_first(_field(data, "image", "sourceImage"), _field(data, "targetImage")),
        command_line=_field(data, "commandLine", "sourceCommandLine"),
    )


def _strong_semantic_identity(
    *, host: Any, event_id: Any, provider: Any, channel: Any, timestamp: Any,
    process_guid: Any, image: Any, command_line: Any,
) -> tuple[str, ...] | None:
    """Return an exact cross-index identity, or ``None`` when it is unsafe.

    Process GUID, exact event time, event ID, and host are mandatory.  This
    deliberately avoids fuzzy time/name matching that could merge two real
    executions of the same command.
    """
    required = (_canonical(host), _canonical(event_id), _canonical_timestamp(timestamp), _canonical(process_guid))
    if not all(required):
        return None
    return (*required, _canonical(provider), _canonical(channel), _canonical(image), _canonical(command_line))


def _canonical(value: Any) -> str:
    return str(value).strip().casefold() if value not in (None, "") else ""


def _canonical_timestamp(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except ValueError:
        return text.casefold()


def _append_source(seed: dict[str, Any], record: Mapping[str, Any]) -> None:
    source = {"alert_id": _string(_alert_id(record)), "document_id": _string(record.get("alert_id") or record.get("_id"))}
    sources = seed.setdefault("sources", [])
    if source not in sources:
        sources.append(source)
    seed["occurrence_count"] = 1


def _event_id(record: Mapping[str, Any]) -> Any:
    return _field(_mapping_path(record, "event", "data", "win", "system"), "eventID") or _mapping(record.get("event")).get("code")


def _record_timestamp(record: Mapping[str, Any]) -> str | None:
    data = _mapping_path(record, "event", "data", "win", "eventdata")
    system = _mapping_path(record, "event", "data", "win", "system")
    return _string(_first(_field(data, "utcTime"), system.get("systemTime"), record.get("timestamp")))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_path(value: Mapping[str, Any], *path: str) -> Mapping[str, Any]:
    current: Any = value
    for key in path:
        current = _mapping(current).get(key)
    return _mapping(current)


def _field(values: Mapping[str, Any], *names: str) -> Any:
    lowered = {str(key).casefold(): item for key, item in values.items()}
    return _first(*(lowered.get(name.casefold()) for name in names))


def _first(*values: Any) -> Any:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
    return None


def _string(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [item for item in _list(value) if isinstance(item, str) and item]
