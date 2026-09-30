"""Universal, observed-field-only normalization for Wazuh alert records.

This module deliberately knows field aliases, not detections or attack types.
It converts a Wazuh/OpenSearch alert into one stable schema that the generic
collection planner can use without requiring an Event-ID-specific dossier.
"""
from __future__ import annotations

from typing import Any, Mapping


def normalize_alert(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical V1 alert object; absent fields are always ``None``."""
    event = _mapping(alert.get("event"))
    win = _mapping_path(event, "data", "win")
    system = _mapping(win.get("system"))
    data = _mapping(win.get("eventdata"))
    rule = _mapping(alert.get("rule"))
    agent = _mapping(alert.get("agent"))
    host = _mapping(event.get("host"))
    process = _mapping(event.get("process"))
    parent = _mapping(process.get("parent"))
    source = _mapping(event.get("source"))
    destination = _mapping(event.get("destination"))
    user = _mapping(event.get("user"))
    file = _mapping(event.get("file"))
    dns = _mapping(event.get("dns"))
    question = _mapping(dns.get("question"))
    url = _mapping(event.get("url"))
    vulnerability = _mapping_path(event, "data", "vulnerability")
    vulnerability_package = _mapping(vulnerability.get("package"))
    vulnerability_score = _mapping(vulnerability.get("score"))

    entities = {
        "host": _first(alert.get("host"), agent.get("name"), host.get("name")),
        "agent_id": _first(alert.get("agent_id"), agent.get("id")),
        "user": _first(_field(data, "user", "targetUserName", "subjectUserName", "sourceUser", "targetUser"), user.get("name")),
        "process_name": _first(_field(data, "image", "sourceImage"), process.get("name"), process.get("executable")),
        "process_path": _first(_field(data, "image", "sourceImage"), process.get("executable")),
        "process_id": _first(_field(data, "processId", "sourceProcessId"), process.get("pid")),
        "process_guid": _first(_field(data, "processGuid", "sourceProcessGuid"), process.get("entity_id")),
        "parent_process_name": _first(_field(data, "parentImage"), parent.get("name"), parent.get("executable")),
        "parent_process_path": _first(_field(data, "parentImage"), parent.get("executable")),
        "parent_process_id": _first(_field(data, "parentProcessId"), parent.get("pid")),
        "parent_process_guid": _field(data, "parentProcessGuid"),
        "command_line": _first(_field(data, "commandLine", "sourceCommandLine"), process.get("command_line")),
        "source_ip": _first(_field(data, "sourceIp", "ipAddress"), source.get("ip")),
        "destination_ip": _first(_field(data, "destinationIp"), destination.get("ip")),
        "destination_port": _first(_field(data, "destinationPort"), destination.get("port")),
        "domain": _first(_field(data, "destinationHostname", "queryName"), question.get("name"), url.get("domain")),
        "file_path": _first(_field(data, "targetFilename", "imageLoaded", "newName"), file.get("path")),
        "file_hashes": _hashes(_first(_field(data, "hashes"), _mapping(file.get("hash")).get("sha256"), _mapping(process.get("hash")).get("sha256"))),
        "registry_key": _field(data, "targetObject"),
        "registry_value": _field(data, "details"),
        "target_process_name": _first(_field(data, "targetImage"), _mapping(event.get("target")).get("process", {}).get("name") if isinstance(_mapping(event.get("target")).get("process"), Mapping) else None),
        "target_process_guid": _field(data, "targetProcessGuid"),
        "service_name": _field(data, "serviceName"),
        "service_image_path": _field(data, "imagePath", "serviceFileName"),
        "service_account": _field(data, "accountName", "serviceAccount"),
        "service_start_type": _field(data, "startType", "serviceStartType"),
        "service_type": _field(data, "serviceType"),
        "vulnerability_cve": _first(vulnerability.get("cve"), vulnerability.get("title")),
        "vulnerability_package": _first(vulnerability_package.get("name")),
        "vulnerability_package_version": _first(vulnerability_package.get("version")),
        "vulnerability_severity": _first(vulnerability.get("severity")),
        "vulnerability_cvss": _first(vulnerability_score.get("base")),
    }
    return {
        "alert_id": _first(alert.get("wazuh_alert_id"), alert.get("id"), alert.get("alert_id")),
        # Prefer the producer's event time over Wazuh/OpenSearch ingestion time.
        # This keeps reports and exact cross-index identity tied to the event
        # that occurred on the endpoint. Other sources safely fall back.
        "timestamp_utc": _first(_field(data, "utcTime"), system.get("systemTime"), alert.get("timestamp"), event.get("created"), event.get("@timestamp")),
        "title": _first(rule.get("description"), alert.get("description")),
        "rule_id": _first(rule.get("id")),
        "severity": _integer(rule.get("level")),
        "source": {
            "channel": _first(system.get("channel"), event.get("dataset")),
            "event_id": _first(system.get("eventID"), event.get("code")),
            "provider": _first(system.get("providerName"), event.get("provider")),
            "groups": _strings(rule.get("groups")),
            "mitre": _mapping(rule.get("mitre")),
        },
        "entities": entities,
        "raw_reference": {
            "index": _first(alert.get("index")),
            "document_id": _first(alert.get("alert_id"), alert.get("_id")),
        },
    }


def unexpected_normalized_values(alert: Mapping[str, Any], normalized: Mapping[str, Any]) -> list[str]:
    """Return normalized scalar values not traceable to the source alert.

    This test-oriented guard treats a hash parsed from a combined hash string
    as derived when it occurs within any original scalar value. It does not
    inspect schema labels or nulls, only values shown to later pipeline stages.
    """
    source_values = _leaf_values(alert)
    unexpected: list[str] = []
    for value in _leaf_values(normalized):
        if value and not any(value == source or value in source for source in source_values):
            unexpected.append(value)
    return unexpected


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_path(value: Mapping[str, Any], *path: str) -> Mapping[str, Any]:
    current: Any = value
    for key in path:
        current = _mapping(current).get(key)
    return _mapping(current)


def _field(value: Mapping[str, Any], *names: str) -> str | None:
    # OpenSearch/Wazuh field spellings differ by source and version. Match keys
    # case-insensitively while preserving the original observed value.
    lowered = {str(key).casefold(): item for key, item in value.items()}
    return _first(*(lowered.get(name.casefold()) for name in names))


def _first(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return None


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None and str(value).strip() else None
    except (TypeError, ValueError):
        return None


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _hashes(value: str | None) -> list[str]:
    if not value:
        return []
    result: list[str] = []
    for item in value.replace(";", ",").split(","):
        candidate = item.split("=", 1)[-1].strip()
        if candidate and candidate not in result:
            result.append(candidate)
    return result


def _leaf_values(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [item for child in value.values() for item in _leaf_values(child)]
    if isinstance(value, list):
        return [item for child in value for item in _leaf_values(child)]
    return [str(value)] if isinstance(value, (str, int, float)) and not isinstance(value, bool) else []
