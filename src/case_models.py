"""Canonical evidence-grounded case model for the V1 investigation contracts."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

try:
    from .sysmon_profile_contracts import PROFILES
except ImportError:
    from sysmon_profile_contracts import PROFILES


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    event_type: str
    timestamp: str | None
    record: dict[str, Any]
    source_ref: dict[str, Any] = field(default_factory=dict)
    detail_level: str = "direct"


@dataclass(frozen=True)
class TimelineEvent:
    evidence_id: str
    timestamp: str | None
    event_type: str
    summary: str


@dataclass
class InvestigationCase:
    case_id: str
    seed_alert_id: str
    evidence: list[Evidence] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    tool_history: list[dict[str, Any]] = field(default_factory=list)
    correlations: dict[str, Any] = field(default_factory=dict)
    contextual_evidence_ids: set[str] = field(default_factory=set)
    entities: dict[str, set[str]] = field(default_factory=lambda: {
        "hosts": set(), "users": set(), "process_guids": set(), "parent_process_guids": set(),
        "processes": set(), "ips": set(), "domains": set(), "hashes": set(),
    })

    def add_alert_evidence(self, alert: Mapping[str, Any], source: str = "wazuh", source_ref: Mapping[str, Any] | None = None, detail_level: str = "direct") -> Evidence:
        compact = _compact_alert(alert, detail_level)
        evidence = Evidence(
            evidence_id=f"E{len(self.evidence) + 1:03d}",
            source=source,
            event_type=_event_type(compact),
            timestamp=_string(compact.get("timestamp")),
            record=compact,
            source_ref=dict(source_ref or {"backend": source, "document_id": compact.get("alert_id")}),
            detail_level=detail_level,
        )
        self.evidence.append(evidence)
        self._extract_entities(compact)
        self.timeline.append(TimelineEvent(evidence.evidence_id, evidence.timestamp, evidence.event_type, _summary(alert)))
        self.timeline.sort(key=lambda item: item.timestamp or "")
        return evidence

    def add_derived_evidence(self, event_type: str, record: Mapping[str, Any], source_evidence_id: str) -> Evidence:
        """Record a deterministic transformation with a traceable source evidence ID."""
        if source_evidence_id not in {item.evidence_id for item in self.evidence}:
            raise ValueError("derived evidence must reference an existing evidence ID")
        evidence = Evidence(
            evidence_id=f"E{len(self.evidence) + 1:03d}", source="deterministic_transform",
            event_type=event_type, timestamp=None,
            record={"source_evidence_id": source_evidence_id, **dict(record)},
            source_ref={"derived_from": source_evidence_id},
        )
        self.evidence.append(evidence)
        self.timeline.append(TimelineEvent(evidence.evidence_id, None, event_type, f"Derived from {source_evidence_id}: {event_type}"))
        return evidence

    def add_tool_result(self, tool: str, arguments: Mapping[str, Any], result: Mapping[str, Any], contextual: bool = False) -> list[Evidence]:
        """Persist every tool invocation and add new normalized Wazuh records."""
        meta = result.get("meta", {}) if isinstance(result.get("meta"), Mapping) else {}
        self.tool_history.append({
            "tool": tool, "arguments": dict(arguments), "ok": bool(result.get("ok")),
            "source": meta.get("source"), "index": meta.get("index"),
            "count": meta.get("count"), "total": meta.get("total"), "truncated": meta.get("truncated"),
        })
        existing = {_event_identity(item.record) for item in self.evidence}
        added: list[Evidence] = []
        for record in result.get("data", []):
            if not isinstance(record, Mapping) or not _string(record.get("alert_id")) or _event_identity(record) in existing:
                continue
            added.append(self.add_alert_evidence(record, source_ref={"backend": meta.get("source"), "index": meta.get("index"), "document_id": record.get("alert_id")}, detail_level="context" if contextual else "direct"))
            if contextual:
                self.contextual_evidence_ids.add(added[-1].evidence_id)
            existing.add(_event_identity(record))
        return added

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["entities"] = {key: sorted(values) for key, values in self.entities.items()}
        payload["contextual_evidence_ids"] = sorted(self.contextual_evidence_ids)
        return payload

    def _extract_entities(self, alert: Mapping[str, Any]) -> None:
        event = alert.get("event", {})
        if not isinstance(event, Mapping):
            return
        win = _mapping_path(event, "data", "win", "eventdata")
        self._add("hosts", alert.get("host"))
        self._add("users", win.get("user") or win.get("targetUserName") or _path(event, "user", "name"))
        self._add("process_guids", win.get("processGuid"))
        self._add("parent_process_guids", win.get("parentProcessGuid"))
        self._add("processes", win.get("image") or _path(event, "process", "name"))
        self._add("processes", win.get("parentImage"))
        for value in (win.get("destinationIp"), win.get("sourceIp"), win.get("ipAddress"), _path(event, "destination", "ip"), _path(event, "source", "ip")):
            self._add("ips", value)
        for value in (win.get("destinationHostname"), _path(event, "dns", "question", "name"), _path(event, "url", "domain")):
            self._add("domains", value)
        for value in (win.get("hashes"), _path(event, "file", "hash", "sha256"), _path(event, "process", "hash", "sha256")):
            self._add_hashes(value)

    def _add(self, category: str, value: Any) -> None:
        text = _string(value)
        if text:
            self.entities[category].add(text)

    def _add_hashes(self, value: Any) -> None:
        if not isinstance(value, str):
            return
        for item in value.replace(";", ",").split(","):
            candidate = item.split("=", 1)[-1].strip()
            if candidate:
                self.entities["hashes"].add(candidate)


class CaseBuilder:
    """Creates a canonical case from the normalized Wazuh tool envelope."""
    @staticmethod
    def from_seed_result(case_id: str, result: Mapping[str, Any]) -> InvestigationCase:
        records = result.get("data", [])
        if not isinstance(records, list) or not records or not isinstance(records[0], Mapping):
            raise ValueError("seed result must contain one normalized Wazuh alert")
        seed = records[0]
        document_id = _string(seed.get("alert_id"))
        analyst_alert_id = _string(seed.get("wazuh_alert_id")) or document_id
        if not document_id or not analyst_alert_id:
            raise ValueError("seed alert must contain alert_id")
        case = InvestigationCase(case_id=case_id, seed_alert_id=analyst_alert_id)
        meta = result.get("meta", {}) if isinstance(result.get("meta"), Mapping) else {}
        case.add_alert_evidence(seed, source_ref={"backend": meta.get("source", "alerts"), "index": meta.get("index"), "document_id": document_id, "wazuh_alert_id": analyst_alert_id}, detail_level="seed")
        return case


_BASE_WIN_EVENTDATA_FIELDS = {
    "processGuid", "parentProcessGuid", "processId", "parentProcessId", "image", "parentImage",
    "commandLine", "user", "targetUserName", "subjectUserName",
    "ipAddress", "sourceIp", "sourcePort", "destinationIp", "destinationPort", "destinationHostname",
    "queryName", "queryStatus", "logonId", "targetLogonId", "logonGuid", "logonType",
    "workstationName", "terminalSessionId", "hashes", "targetFilename", "imageLoaded",
    "queryName", "queryStatus", "protocol", "initiated", "eventType", "targetObject", "details", "newName",
}
_PROFILE_EVENTDATA_FIELDS = {
    alias
    for contract in PROFILES
    for _, aliases in (contract.required_keys + contract.dossier_fields)
    for alias in aliases
}
_WIN_EVENTDATA_FIELDS = _BASE_WIN_EVENTDATA_FIELDS | _PROFILE_EVENTDATA_FIELDS


def _compact_alert(alert: Mapping[str, Any], detail_level: str = "direct") -> dict[str, Any]:
    """Keep only fields that can support an investigation; Wazuh remains raw source of truth."""
    event = alert.get("event", {}) if isinstance(alert.get("event"), Mapping) else {}
    win = _mapping_path(event, "data", "win")
    eventdata = win.get("eventdata", {}) if isinstance(win.get("eventdata"), Mapping) else {}
    system = win.get("system", {}) if isinstance(win.get("system"), Mapping) else {}
    fields = _WIN_EVENTDATA_FIELDS if detail_level != "context" else {"processGuid", "parentProcessGuid", "processId", "image", "user", "destinationIp", "destinationPort", "sourceProcessGuid", "targetProcessGuid", "sourceImage", "targetImage", "targetObject", "targetFilename", "queryName"}
    compact_event: dict[str, Any] = {"data": {"win": {
        "system": {key: system[key] for key in ("eventID", "eventRecordID", "channel", "providerName", "systemTime") if system.get(key) not in (None, "")},
        "eventdata": {key: eventdata[key] for key in fields if eventdata.get(key) not in (None, "")},
    }}}
    for key in ("process", "destination", "source", "dns", "url", "user", "file"):
        if isinstance(event.get(key), Mapping):
            compact_event[key] = dict(event[key])
    rule = alert.get("rule", {}) if isinstance(alert.get("rule"), Mapping) else {}
    return {
        "alert_id": alert.get("alert_id"), "wazuh_alert_id": alert.get("wazuh_alert_id"), "timestamp": alert.get("timestamp"), "host": alert.get("host"), "agent_id": alert.get("agent_id"),
        "rule": {key: rule.get(key) for key in ("id", "level", "description", "groups", "mitre") if key in rule}, "event": compact_event,
    }


def _event_identity(alert: Mapping[str, Any]) -> str:
    event_record_id = _path(alert, "event", "data", "win", "system", "eventRecordID")
    agent_id = alert.get("agent_id")
    if event_record_id not in (None, "") and agent_id not in (None, ""):
        return f"event:{agent_id}:{event_record_id}"
    return f"document:{alert.get('alert_id')}"


def _event_type(alert: Mapping[str, Any]) -> str:
    event = alert.get("event", {})
    event_id = _path(event, "data", "win", "system", "eventID")
    if str(event_id) == "1":
        return "process_creation"
    if str(event_id) == "3":
        return "network_connection"
    if str(event_id) == "7":
        return "image_load"
    if str(event_id) == "10":
        return "process_access"
    if str(event_id) == "11":
        return "file_create"
    if str(event_id) in {"12", "13", "14"}:
        return "registry_event"
    if str(event_id) == "22":
        return "dns_query"
    if str(event_id) in {"4624", "4625", "4634", "4647", "4648", "4672", "4768", "4769", "4771", "4776"}:
        return "authentication"
    groups = alert.get("rule", {}).get("groups", []) if isinstance(alert.get("rule"), Mapping) else []
    if "sca" in groups:
        return "configuration_assessment"
    if any("authentication" in str(group).lower() for group in groups):
        return "authentication"
    return "wazuh_alert"


def _summary(alert: Mapping[str, Any]) -> str:
    rule = alert.get("rule", {})
    description = rule.get("description") if isinstance(rule, Mapping) else None
    return str(description or "Wazuh alert")


def _mapping_path(value: Any, *path: str) -> Mapping[str, Any]:
    current: Any = value
    for component in path:
        if not isinstance(current, Mapping):
            return {}
        current = current.get(component)
    return current if isinstance(current, Mapping) else {}


def _path(value: Any, *path: str) -> Any:
    current: Any = value
    for component in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(component)
    return current


def _string(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
