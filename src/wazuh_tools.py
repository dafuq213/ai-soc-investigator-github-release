"""Controlled, read-only investigation tools for Wazuh and Wazuh Indexer.

The agent must call this module's functions, never either backend directly.  Each
function returns the same JSON-serialisable envelope so that the next agent step
can reliably ground its decision in returned identifiers and values.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


Transport = Callable[[str, str, Mapping[str, str], dict[str, Any] | None], tuple[int, dict[str, Any]]]
_SAFE_FIELD_NAMES = {
    "agent.name", "agent.id", "host.name", "user.name", "data.win.eventdata.image",
    "data.win.eventdata.parentimage", "data.win.eventdata.commandLine", "process.name",
    "process.parent.name", "process.command_line", "destination.ip", "destination.port",
    "source.ip", "url.domain", "dns.question.name", "rule.id", "rule.groups",
    "rule.level", "rule.description", "event.module", "event.dataset",
    "data.win.eventdata.targetObject", "data.win.eventdata.details",
}
_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,256}$")
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,128}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_FIXTURE_MARKER_RE = re.compile(r"^SOC_(?:PROCESS|SYSMON)_FIXTURE_[A-Za-z0-9_]{1,160}$")
_SYSMON_PROFILE_EVENT_IDS = frozenset({"1", "3", "7", "10", "11", "12", "13", "14", "22"})
_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
_ENTITY_ACTIVITY_TYPES = frozenset({"process_guid", "parent_process_guid", "registry_key", "file_path", "hash", "ip", "domain"})


@dataclass(frozen=True)
class WazuhConfig:
    indexer_url: str
    indexer_username: str
    indexer_password: str
    alert_index: str = "wazuh-alerts-*"
    telemetry_index: str | None = None
    api_url: str | None = None
    api_username: str | None = None
    api_password: str | None = None
    verify_tls: bool = True
    timeout_seconds: int = 10

    @classmethod
    def from_env(cls) -> "WazuhConfig":
        _load_local_config()
        required = ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USERNAME", "WAZUH_INDEXER_PASSWORD")
        missing = [name for name in required if not os.getenv(name)]
        if missing:
            raise ValueError("Missing required configuration: " + ", ".join(missing))
        return cls(
            indexer_url=os.environ["WAZUH_INDEXER_URL"].rstrip("/"),
            indexer_username=os.environ["WAZUH_INDEXER_USERNAME"],
            indexer_password=os.environ["WAZUH_INDEXER_PASSWORD"],
            alert_index=os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts-*"),
            telemetry_index=os.getenv("WAZUH_TELEMETRY_INDEX", "").strip() or None,
            api_url=os.getenv("WAZUH_API_URL", "").rstrip("/") or None,
            api_username=os.getenv("WAZUH_API_USERNAME") or None,
            api_password=os.getenv("WAZUH_API_PASSWORD") or None,
            verify_tls=os.getenv("WAZUH_VERIFY_TLS", "true").lower() == "true",
        )


def _load_local_config() -> None:
    """Load local configuration without overriding deployment-provided variables."""
    root = Path(__file__).resolve().parent.parent
    allowed = ("WAZUH_", "LLM_", "QA_", "OLLAMA_", "OPENAI_", "ANTHROPIC_", "GEMINI_")
    for path in (root / ".env", root / ".wazuh.local.env"):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip().startswith(allowed):
                os.environ.setdefault(key.strip(), value.strip())


class BackendError(RuntimeError):
    pass


class WazuhToolLayer:
    """Read-only and bounded Wazuh investigation surface."""

    def __init__(self, config: WazuhConfig, transport: Transport | None = None):
        self.config = config
        self._transport = transport or self._http_transport

    def get_alerts(self, severity: int, limit: int = 25) -> dict[str, Any]:
        if not isinstance(severity, int) or not 0 <= severity <= 16:
            return self._error("get_alerts", "validation_error", "severity must be an integer from 0 to 16")
        validation = self._limit(limit)
        if validation:
            return self._error("get_alerts", "validation_error", validation)
        return self._search("get_alerts", {"term": {"rule.level": severity}}, limit)

    def get_alert_by_id(self, alert_id: str) -> dict[str, Any]:
        if not isinstance(alert_id, str) or not _ID_RE.fullmatch(alert_id):
            return self._error("get_alert_by_id", "validation_error", "alert_id has an invalid format")
        # Operators see Wazuh's event ID in the UI, while OpenSearch also has
        # its own document ID.  Support both representations without exposing
        # a general query surface.  Some index templates map `id` as text with
        # a keyword subfield; others map it directly as a keyword.
        query = {"bool": {"should": [
            {"ids": {"values": [alert_id]}},
            {"term": {"id": alert_id}},
            {"term": {"id.keyword": alert_id}},
            {"match_phrase": {"id": alert_id}},
        ], "minimum_should_match": 1}}
        return self._search("get_alert_by_id", query, 1)

    def search_logs(self, query: Mapping[str, Any], limit: int = 50) -> dict[str, Any]:
        """Search with a small allowlisted filter language, never raw OpenSearch DSL.

        query example: {"filters": [{"field": "agent.name", "operator": "equals",
        "value": "workstation-01"}], "hours": 24}
        """
        validation = self._limit(limit) or self._validate_log_query(query)
        if validation:
            return self._error("search_logs", "validation_error", validation)
        clauses = [self._filter_to_clause(item) for item in query.get("filters", [])]
        hours = query.get("hours", 24)
        clauses.append({"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}})
        return self._search("search_logs", {"bool": {"filter": clauses}}, limit)

    def get_host_process_activity(self, host: str, limit: int = 50) -> dict[str, Any]:
        return self._host_activity("get_host_process_activity", host, ["data.win.eventdata.image", "process.name"], limit)

    def get_process_fixture_by_marker(self, marker: str, host: str, hours: int = 1) -> dict[str, Any]:
        """Test-only exact lookup for a generated fixture marker.

        It is deliberately absent from the LLM tool registry. The marker is
        created by the local lab runner, restricts the query to one host and
        Sysmon Event ID 1, and prevents an active endpoint's background events
        from contaminating fixture capture.
        """
        if not isinstance(marker, str) or not _FIXTURE_MARKER_RE.fullmatch(marker):
            return self._error("get_process_fixture_by_marker", "validation_error", "marker must be a generated SOC_PROCESS_FIXTURE or SOC_SYSMON_FIXTURE value")
        if not self._valid_value(host):
            return self._error("get_process_fixture_by_marker", "validation_error", "host must be a non-empty string of 256 characters or fewer")
        if not isinstance(hours, int) or not 1 <= hours <= 24:
            return self._error("get_process_fixture_by_marker", "validation_error", "hours must be an integer from 1 to 24")
        query = {"bool": {"filter": [
            {"bool": {"should": [{"term": {"agent.name": host}}, {"term": {"host.name": host}}], "minimum_should_match": 1}},
            {"term": {"data.win.system.eventID": "1"}},
            # The caller supplies the marker through a file or environment
            # variable, not on the collector command line. Therefore an exact
            # generated marker plus host and Event ID is sufficient and works
            # for every controlled fixture script, not only one script name.
            {"wildcard": {"data.win.eventdata.commandLine": f"*{marker}*"}},
            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        ]}}
        return self._search_telemetry("get_process_fixture_by_marker", query, 1)

    def get_sysmon_fixture_process(self, marker: str, host: str, process_id: str, hours: int = 1) -> dict[str, Any]:
        """Test-only exact child-process lookup using generated marker and PID.

        The marker may also occur in a parent launcher command line. Requiring
        the child PID avoids falsely selecting that launcher during live fixture
        capture; the marker still prevents PID reuse from matching another run.
        """
        if not isinstance(marker, str) or not _FIXTURE_MARKER_RE.fullmatch(marker):
            return self._error("get_sysmon_fixture_process", "validation_error", "marker must be a generated fixture value")
        if not self._valid_value(host) or not self._valid_value(process_id) or not process_id.isdigit():
            return self._error("get_sysmon_fixture_process", "validation_error", "host and numeric process_id are required")
        if not isinstance(hours, int) or not 1 <= hours <= 24:
            return self._error("get_sysmon_fixture_process", "validation_error", "hours must be an integer from 1 to 24")
        query = {"bool": {"filter": [
            {"bool": {"should": [{"term": {"agent.name": host}}, {"term": {"host.name": host}}], "minimum_should_match": 1}},
            {"term": {"data.win.system.eventID": "1"}},
            {"term": {"data.win.eventdata.processId": process_id}},
            {"wildcard": {"data.win.eventdata.commandLine": "*run_sysmon_multimodal_fixture.ps1*"}},
            {"wildcard": {"data.win.eventdata.commandLine": "*-Child*"}},
            {"wildcard": {"data.win.eventdata.commandLine": f"*{marker}*"}},
            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        ]}}
        return self._search_telemetry("get_sysmon_fixture_process", query, 1)

    def get_network_activity(self, host: str, limit: int = 50) -> dict[str, Any]:
        return self._host_activity("get_network_activity", host, ["data.win.eventdata.destinationIp", "destination.ip"], limit)

    def get_dns_activity(self, host: str, limit: int = 50) -> dict[str, Any]:
        return self._host_activity("get_dns_activity", host, ["data.win.eventdata.queryName", "dns.question.name"], limit)

    def get_host_file_activity(self, host: str, limit: int = 50) -> dict[str, Any]:
        return self._host_activity("get_host_file_activity", host, ["data.win.eventdata.targetFilename", "file.path"], limit)

    def get_hash_activity(self, hash_value: str, hours: int = 24, limit: int = 50) -> dict[str, Any]:
        if not isinstance(hash_value, str) or not _HASH_RE.fullmatch(hash_value):
            return self._error("get_hash_activity", "validation_error", "hash_value must be a 32-128 character hexadecimal hash")
        if not isinstance(hours, int) or not 1 <= hours <= 168:
            return self._error("get_hash_activity", "validation_error", "hours must be an integer from 1 to 168")
        validation = self._limit(limit)
        if validation:
            return self._error("get_hash_activity", "validation_error", validation)
        query = {"bool": {"filter": [
            {"bool": {"should": [
                {"wildcard": {"data.win.eventdata.hashes": f"*{hash_value.upper()}*"}},
                {"term": {"file.hash.sha256": hash_value.lower()}},
                {"term": {"process.hash.sha256": hash_value.lower()}},
            ], "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        ]}}
        return self._search_telemetry("get_hash_activity", query, limit)

    def get_ip_activity(self, ip: str, hours: int = 24, limit: int = 50) -> dict[str, Any]:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self._error("get_ip_activity", "validation_error", "ip must be a valid IPv4 or IPv6 address")
        if not isinstance(hours, int) or not 1 <= hours <= 168:
            return self._error("get_ip_activity", "validation_error", "hours must be an integer from 1 to 168")
        validation = self._limit(limit)
        if validation:
            return self._error("get_ip_activity", "validation_error", validation)
        query = {"bool": {"filter": [
            {"bool": {"should": [
                {"term": {"data.win.eventdata.destinationIp": ip}}, {"term": {"data.win.eventdata.sourceIp": ip}},
                {"term": {"destination.ip": ip}}, {"term": {"source.ip": ip}},
            ], "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        ]}}
        return self._search_telemetry("get_ip_activity", query, limit)

    def get_domain_activity(self, domain: str, hours: int = 24, limit: int = 50) -> dict[str, Any]:
        if not isinstance(domain, str) or not _DOMAIN_RE.fullmatch(domain):
            return self._error("get_domain_activity", "validation_error", "domain must be a valid hostname")
        if not isinstance(hours, int) or not 1 <= hours <= 168:
            return self._error("get_domain_activity", "validation_error", "hours must be an integer from 1 to 168")
        validation = self._limit(limit)
        if validation:
            return self._error("get_domain_activity", "validation_error", validation)
        query = {"bool": {"filter": [
            {"bool": {"should": [
                {"term": {"data.win.eventdata.queryName": domain}}, {"term": {"data.win.eventdata.destinationHostname": domain}},
                {"term": {"dns.question.name": domain}}, {"term": {"url.domain": domain}},
            ], "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        ]}}
        return self._search_telemetry("get_domain_activity", query, limit)

    def get_process_by_guid(self, process_guid: str, hours: int = 24, limit: int = 25, agent_id: str | None = None) -> dict[str, Any]:
        """Return the Sysmon process-creation record for an exact process GUID.

        A process GUID can also occur in termination telemetry (Event ID 5),
        which lacks parent and command-line fields. Lineage collection must use
        Event ID 1 only so the first returned record is a usable creation event.
        """
        return self._process_query("get_process_by_guid", "data.win.eventdata.processGuid", process_guid, hours, limit, agent_id, event_ids=("1",))

    def get_entity_activity(self, entity_type: str, value: str, start_time: str, end_time: str, limit: int = 10, agent_id: str | None = None, host: str | None = None) -> dict[str, Any]:
        """Get same-host, time-bounded activity for one allowlisted entity.

        This is intentionally not a generic field-search API. ``entity_type``
        maps to a fixed set of indexed fields, while the planner supplies only
        values observed in the seed alert.
        """
        if entity_type not in _ENTITY_ACTIVITY_TYPES:
            return self._error("get_entity_activity", "validation_error", "entity_type is not supported")
        if not self._valid_value(value):
            return self._error("get_entity_activity", "validation_error", "value must be a non-empty string of 256 characters or fewer")
        if bool(agent_id) == bool(host):
            return self._error("get_entity_activity", "validation_error", "exactly one of agent_id or host is required")
        if agent_id and not self._valid_value(agent_id) or host and not self._valid_value(host):
            return self._error("get_entity_activity", "validation_error", "agent_id or host is invalid")
        validation = self._limit(limit) or self._time_range(start_time, end_time, max_hours=24)
        if validation:
            return self._error("get_entity_activity", "validation_error", validation)
        scope = {"term": {"agent.id": agent_id}} if agent_id else {"bool": {"should": [{"term": {"agent.name": host}}, {"term": {"host.name": host}}], "minimum_should_match": 1}}
        query = {"bool": {"filter": [
            scope, _entity_activity_clause(entity_type, value),
            {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
        ]}}
        return self._search_telemetry("get_entity_activity", query, limit)

    def get_process_children(self, parent_process_guid: str, hours: int = 24, limit: int = 25, agent_id: str | None = None) -> dict[str, Any]:
        return self._process_query("get_process_children", "data.win.eventdata.parentProcessGuid", parent_process_guid, hours, limit, agent_id, event_ids=("1",))

    def get_process_network_activity(self, process_guid: str, hours: int = 24, limit: int = 25, agent_id: str | None = None) -> dict[str, Any]:
        if not self._valid_value(process_guid):
            return self._error("get_process_network_activity", "validation_error", "process_guid must be a non-empty string of 256 characters or fewer")
        if not isinstance(hours, int) or not 1 <= hours <= 168:
            return self._error("get_process_network_activity", "validation_error", "hours must be an integer from 1 to 168")
        validation = self._limit(limit)
        if validation:
            return self._error("get_process_network_activity", "validation_error", validation)
        query = {"bool": {"filter": [
            {"term": {"data.win.eventdata.processGuid": process_guid}},
            *([{"term": {"agent.id": agent_id}}] if agent_id else []),
            {"exists": {"field": "data.win.eventdata.destinationIp"}},
            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        ]}}
        return self._search_telemetry("get_process_network_activity", query, limit)

    def get_process_siblings(self, parent_process_guid: str, agent_id: str, start_time: str, end_time: str, limit: int = 25) -> dict[str, Any]:
        """Return nearby same-parent processes as contextual, not causal, evidence."""
        if not self._valid_value(parent_process_guid) or not self._valid_value(agent_id):
            return self._error("get_process_siblings", "validation_error", "parent_process_guid and agent_id are required")
        validation = self._limit(limit)
        if validation:
            return self._error("get_process_siblings", "validation_error", validation)
        try:
            start, end = datetime.fromisoformat(start_time.replace("Z", "+00:00")), datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            if end <= start or end - start > timedelta(minutes=10):
                raise ValueError
        except (AttributeError, ValueError):
            return self._error("get_process_siblings", "validation_error", "time range must be ISO-8601 and no longer than 10 minutes")
        query = {"bool": {"filter": [
            {"term": {"agent.id": agent_id}}, {"term": {"data.win.eventdata.parentProcessGuid": parent_process_guid}},
            {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
        ]}}
        return self._search_telemetry("get_process_siblings", query, limit)

    def get_sysmon_profile_events(self, process_guid: str, agent_id: str, start_time: str, end_time: str, event_ids: list[str], relationship: str, limit: int = 25) -> dict[str, Any]:
        """Return only a profile-defined, exact Sysmon GUID relationship.

        This tool is intentionally narrower than a generic event search. The
        profile layer supplies the static relationship and event family; callers
        cannot submit arbitrary fields or raw OpenSearch DSL.
        """
        if not self._valid_value(process_guid) or not self._valid_value(agent_id):
            return self._error("get_sysmon_profile_events", "validation_error", "process_guid and agent_id are required")
        if relationship not in {"actor", "child", "access"}:
            return self._error("get_sysmon_profile_events", "validation_error", "relationship must be actor, child, or access")
        if not isinstance(event_ids, list) or not event_ids or not all(isinstance(item, str) and item in _SYSMON_PROFILE_EVENT_IDS for item in event_ids):
            return self._error("get_sysmon_profile_events", "validation_error", "event_ids must be supported Sysmon event IDs")
        if relationship == "child" and event_ids != ["1"]:
            return self._error("get_sysmon_profile_events", "validation_error", "child relationship requires Sysmon Event ID 1")
        if relationship == "access" and event_ids != ["10"]:
            return self._error("get_sysmon_profile_events", "validation_error", "access relationship requires Sysmon Event ID 10")
        validation = self._limit(limit) or self._time_range(start_time, end_time, max_hours=169)
        if validation:
            return self._error("get_sysmon_profile_events", "validation_error", validation)
        if relationship == "actor":
            relationship_filter: dict[str, Any] = {"term": {"data.win.eventdata.processGuid": process_guid}}
        elif relationship == "child":
            relationship_filter = {"term": {"data.win.eventdata.parentProcessGuid": process_guid}}
        else:
            relationship_filter = {"bool": {"should": [
                {"term": {"data.win.eventdata.sourceProcessGuid": process_guid}},
                {"term": {"data.win.eventdata.sourceProcessGUID": process_guid}},
                {"term": {"data.win.eventdata.targetProcessGuid": process_guid}},
                {"term": {"data.win.eventdata.targetProcessGUID": process_guid}},
            ], "minimum_should_match": 1}}
        query = {"bool": {"filter": [
            {"term": {"agent.id": agent_id}}, relationship_filter,
            {"term": {"data.win.system.providerName": _SYSMON_PROVIDER}},
            {"bool": {"should": [{"term": {"data.win.system.eventID": event_id}} for event_id in event_ids], "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
        ]}}
        return self._search_telemetry("get_sysmon_profile_events", query, limit)

    def get_sysmon_profile_coverage(self, agent_id: str, start_time: str, end_time: str, event_ids: list[str], limit: int = 100) -> dict[str, Any]:
        """Bounded diagnostic query for profile ingestion coverage.

        It is used only to establish whether a configured Sysmon event family
        reached Wazuh. It does not accept fields, values, or raw query DSL.
        """
        if not self._valid_value(agent_id):
            return self._error("get_sysmon_profile_coverage", "validation_error", "agent_id is required")
        if not isinstance(event_ids, list) or not event_ids or not all(isinstance(item, str) and item in _SYSMON_PROFILE_EVENT_IDS for item in event_ids):
            return self._error("get_sysmon_profile_coverage", "validation_error", "event_ids must be supported Sysmon event IDs")
        validation = self._limit(limit) or self._time_range(start_time, end_time, max_hours=24)
        if validation:
            return self._error("get_sysmon_profile_coverage", "validation_error", validation)
        query = {"bool": {"filter": [
            {"term": {"agent.id": agent_id}},
            {"term": {"data.win.system.providerName": _SYSMON_PROVIDER}},
            {"bool": {"should": [{"term": {"data.win.system.eventID": event_id}} for event_id in event_ids], "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
        ]}}
        return self._search_telemetry("get_sysmon_profile_coverage", query, limit)

    def get_sysmon_alert_coverage(self, agent_id: str, start_time: str, end_time: str, event_ids: list[str], limit: int = 100) -> dict[str, Any]:
        """Return actual Wazuh alerts for a bounded Sysmon event family.

        Archive events are evidence sources; this diagnostic makes it explicit
        whether the manager also produced a detection alert for the same
        records. It deliberately accepts no free-form search input.
        """
        if not self._valid_value(agent_id):
            return self._error("get_sysmon_alert_coverage", "validation_error", "agent_id is required")
        if not isinstance(event_ids, list) or not event_ids or not all(isinstance(item, str) and item in _SYSMON_PROFILE_EVENT_IDS for item in event_ids):
            return self._error("get_sysmon_alert_coverage", "validation_error", "event_ids must be supported Sysmon event IDs")
        validation = self._limit(limit) or self._time_range(start_time, end_time, max_hours=24)
        if validation:
            return self._error("get_sysmon_alert_coverage", "validation_error", validation)
        query = {"bool": {"filter": [
            {"term": {"agent.id": agent_id}},
            {"term": {"data.win.system.providerName": _SYSMON_PROVIDER}},
            {"bool": {"should": [{"term": {"data.win.system.eventID": event_id}} for event_id in event_ids], "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
        ]}}
        return self._search("get_sysmon_alert_coverage", query, limit)

    def get_telemetry_status(self) -> dict[str, Any]:
        """Verify the optional raw-telemetry index without exposing raw OpenSearch access."""
        if not self.config.telemetry_index:
            return self._error("get_telemetry_status", "configuration_error", "WAZUH_TELEMETRY_INDEX is not configured")
        return self._search("get_telemetry_status", {"match_all": {}}, 1, self.config.telemetry_index, "telemetry")

    def get_authentication_activity(self, user: str | None = None, source_ip: str | None = None, hours: int = 24, limit: int = 50, agent_id: str | None = None, start_time: str | None = None, end_time: str | None = None) -> dict[str, Any]:
        """Retrieve bounded Windows authentication evidence using observed identity/IP values."""
        if not user and not source_ip:
            return self._error("get_authentication_activity", "validation_error", "user or source_ip is required")
        if (user and not self._valid_value(user)) or (source_ip and not self._valid_value(source_ip)):
            return self._error("get_authentication_activity", "validation_error", "user and source_ip must be non-empty strings of 256 characters or fewer")
        if not isinstance(hours, int) or not 1 <= hours <= 168:
            return self._error("get_authentication_activity", "validation_error", "hours must be an integer from 1 to 168")
        validation = self._limit(limit)
        if validation:
            return self._error("get_authentication_activity", "validation_error", validation)
        filters = [{"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}]
        if agent_id:
            if not self._valid_value(agent_id):
                return self._error("get_authentication_activity", "validation_error", "agent_id must be a non-empty string")
            filters.append({"term": {"agent.id": agent_id}})
        if start_time and end_time:
            filters[0] = {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
        elif start_time or end_time:
            return self._error("get_authentication_activity", "validation_error", "start_time and end_time must be provided together")
        filters.append({"term": {"data.win.system.channel": "Security"}})
        filters.append({"bool": {"should": [{"term": {"data.win.system.eventID": str(event_id)}} for event_id in (4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776)], "minimum_should_match": 1}})
        if user:
            filters.append({"bool": {"should": [{"term": {"data.win.eventdata.targetUserName": user}}, {"term": {"data.win.eventdata.user": user}}, {"term": {"user.name": user}}], "minimum_should_match": 1}})
        if source_ip:
            filters.append({"bool": {"should": [{"term": {"data.win.eventdata.ipAddress": source_ip}}, {"term": {"data.win.eventdata.sourceIp": source_ip}}, {"term": {"source.ip": source_ip}}], "minimum_should_match": 1}})
        return self._search_telemetry("get_authentication_activity", {"bool": {"filter": filters}}, limit)

    def get_agents(self, status: str = "active") -> dict[str, Any]:
        """Example Wazuh manager API call; useful for later response validation."""
        if status not in {"active", "disconnected", "never_connected", "pending", "all"}:
            return self._error("get_agents", "validation_error", "invalid agent status")
        if not self.config.api_url:
            return self._error("get_agents", "configuration_error", "WAZUH_API_URL is not configured")
        try:
            token = self._get_api_token()
            parameters = {"limit": 100}
            if status != "all":
                parameters["status"] = status
            url = f"{self.config.api_url}/agents?{urlencode(parameters)}"
            code, body = self._transport("GET", url, {"Authorization": f"Bearer {token}"}, None)
            if not 200 <= code < 300:
                raise BackendError(f"Wazuh API returned HTTP {code}")
            return self._ok("get_agents", body.get("data", {}).get("affected_items", []), {"count": body.get("data", {}).get("total_affected_items", 0)})
        except (BackendError, HTTPError, URLError, ValueError) as exc:
            return self._error("get_agents", "backend_error", str(exc))

    def _host_activity(self, tool: str, host: str, activity_fields: list[str], limit: int) -> dict[str, Any]:
        if not self._valid_value(host):
            return self._error(tool, "validation_error", "host must be a non-empty string of 256 characters or fewer")
        validation = self._limit(limit)
        if validation:
            return self._error(tool, "validation_error", validation)
        query = {"bool": {"filter": [
            {"bool": {"should": [{"term": {"agent.name": host}}, {"term": {"host.name": host}}], "minimum_should_match": 1}},
            {"bool": {"should": [{"exists": {"field": field}} for field in activity_fields], "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
        ]}}
        return self._search_telemetry(tool, query, limit)

    def _process_query(self, tool: str, field: str, value: str, hours: int, limit: int, agent_id: str | None = None, event_ids: tuple[str, ...] = ()) -> dict[str, Any]:
        if not self._valid_value(value):
            return self._error(tool, "validation_error", "process GUID must be a non-empty string of 256 characters or fewer")
        if not isinstance(hours, int) or not 1 <= hours <= 168:
            return self._error(tool, "validation_error", "hours must be an integer from 1 to 168")
        validation = self._limit(limit)
        if validation:
            return self._error(tool, "validation_error", validation)
        query = {"bool": {"filter": [
            {"term": {field: value}},
            *([{"term": {"agent.id": agent_id}}] if agent_id else []),
            *([{"bool": {"should": [{"term": {"data.win.system.eventID": event_id}} for event_id in event_ids], "minimum_should_match": 1}}] if event_ids else []),
            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        ]}}
        return self._search_telemetry(tool, query, limit)

    @staticmethod
    def _time_range(start_time: Any, end_time: Any, max_hours: int) -> str | None:
        if not isinstance(start_time, str) or not isinstance(end_time, str):
            return "start_time and end_time must be ISO-8601 strings"
        try:
            start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            end = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        except ValueError:
            return "start_time and end_time must be ISO-8601 strings"
        if end <= start or end - start > timedelta(hours=max_hours):
            return f"time range must be positive and no longer than {max_hours} hours"
        return None

    def _search_telemetry(self, tool: str, query: dict[str, Any], limit: int) -> dict[str, Any]:
        """Use raw telemetry when configured; alert data remains a safe fallback."""
        index = self.config.telemetry_index or self.config.alert_index
        kind = "telemetry" if self.config.telemetry_index else "alerts_fallback"
        return self._search(tool, query, limit, index, kind)

    def _search(self, tool: str, query: dict[str, Any], limit: int, index: str | None = None, source_kind: str = "alerts") -> dict[str, Any]:
        body = {"size": limit, "track_total_hits": True, "sort": [{"@timestamp": "desc"}], "query": query}
        try:
            selected_index = index or self.config.alert_index
            url = f"{self.config.indexer_url}/{quote(selected_index, safe='*,-')}/_search"
            code, response = self._transport("POST", url, self._basic_headers(), body)
            if not 200 <= code < 300:
                raise BackendError(f"OpenSearch returned HTTP {code}")
            hits = response.get("hits", {})
            records = [self._normalise_alert(hit) for hit in hits.get("hits", [])]
            total = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
            return self._ok(tool, records, {"count": len(records), "total": total, "truncated": total > len(records), "source": source_kind, "index": selected_index})
        except (BackendError, HTTPError, URLError, ValueError, KeyError) as exc:
            return self._error(tool, "backend_error", str(exc))

    @staticmethod
    def _normalise_alert(hit: Mapping[str, Any]) -> dict[str, Any]:
        source = hit.get("_source", {})
        agent = source.get("agent", {})
        rule = source.get("rule", {})
        # Keep the OpenSearch document ID for retrieval, but expose Wazuh's
        # event ID separately for analyst-facing case traceability.
        return {"alert_id": hit.get("_id"), "wazuh_alert_id": source.get("id"), "timestamp": source.get("@timestamp") or source.get("timestamp"),
                "host": agent.get("name") or source.get("host", {}).get("name"), "agent_id": agent.get("id"),
                "rule": {"id": rule.get("id"), "level": rule.get("level"), "description": rule.get("description"), "groups": rule.get("groups", []), "mitre": rule.get("mitre", {})},
                "event": source}

    def _get_api_token(self) -> str:
        if not self.config.api_username or not self.config.api_password:
            raise BackendError("WAZUH_API_USERNAME and WAZUH_API_PASSWORD are required")
        credentials = base64.b64encode(f"{self.config.api_username}:{self.config.api_password}".encode()).decode()
        code, body = self._transport("POST", f"{self.config.api_url}/security/user/authenticate", {"Authorization": f"Basic {credentials}"}, None)
        if not 200 <= code < 300 or not body.get("data", {}).get("token"):
            raise BackendError("Wazuh API authentication failed")
        return body["data"]["token"]

    def _basic_headers(self) -> dict[str, str]:
        encoded = base64.b64encode(f"{self.config.indexer_username}:{self.config.indexer_password}".encode()).decode()
        return {"Authorization": f"Basic {encoded}", "Content-Type": "application/json"}

    def _http_transport(self, method: str, url: str, headers: Mapping[str, str], payload: dict[str, Any] | None) -> tuple[int, dict[str, Any]]:
        request = Request(url, data=json.dumps(payload).encode() if payload is not None else None, headers=dict(headers), method=method)
        context = None if self.config.verify_tls else ssl._create_unverified_context()
        try:
            with urlopen(request, timeout=self.config.timeout_seconds, context=context) as response:
                return response.status, json.loads(response.read().decode())
        except HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise BackendError(f"HTTP {exc.code}: {detail}") from exc

    @staticmethod
    def _ok(tool: str, data: Any, meta: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "tool": tool, "data": data, "meta": meta, "error": None}

    @staticmethod
    def _error(tool: str, code: str, message: str) -> dict[str, Any]:
        return {"ok": False, "tool": tool, "data": [], "meta": {}, "error": {"code": code, "message": message}}

    @staticmethod
    def _limit(limit: Any) -> str | None:
        return None if isinstance(limit, int) and 1 <= limit <= 100 else "limit must be an integer from 1 to 100"

    @staticmethod
    def _valid_value(value: Any) -> bool:
        return isinstance(value, str) and bool(value.strip()) and len(value) <= 256

    def _validate_log_query(self, query: Any) -> str | None:
        if not isinstance(query, Mapping) or set(query) - {"filters", "hours"}:
            return "query accepts only filters and hours"
        filters, hours = query.get("filters", []), query.get("hours", 24)
        if not isinstance(filters, list) or not 1 <= len(filters) <= 5:
            return "filters must contain 1 to 5 filters"
        if not isinstance(hours, int) or not 1 <= hours <= 168:
            return "hours must be an integer from 1 to 168"
        for item in filters:
            if not isinstance(item, Mapping) or set(item) != {"field", "operator", "value"}:
                return "each filter requires field, operator, and value"
            if item["field"] not in _SAFE_FIELD_NAMES or item["operator"] not in {"equals", "contains"} or not self._valid_value(item["value"]):
                return "filter contains an unsupported field, operator, or value"
        return None

    @staticmethod
    def _filter_to_clause(item: Mapping[str, str]) -> dict[str, Any]:
        return {"term": {item["field"]: item["value"]}} if item["operator"] == "equals" else {"match_phrase": {item["field"]: item["value"]}}


def _entity_activity_clause(entity_type: str, value: str) -> dict[str, Any]:
    """Fixed field mapping used by get_entity_activity; never accepts fields."""
    fields = {
        "process_guid": ("data.win.eventdata.processGuid", "data.win.eventdata.sourceProcessGuid", "data.win.eventdata.sourceProcessGUID", "data.win.eventdata.targetProcessGuid", "data.win.eventdata.targetProcessGUID"),
        "parent_process_guid": ("data.win.eventdata.parentProcessGuid", "data.win.eventdata.parentProcessGUID"),
        "registry_key": ("data.win.eventdata.targetObject",),
        "file_path": ("data.win.eventdata.targetFilename", "data.win.eventdata.imageLoaded", "file.path"),
        "ip": ("data.win.eventdata.destinationIp", "data.win.eventdata.sourceIp", "data.win.eventdata.ipAddress", "destination.ip", "source.ip"),
        "domain": ("data.win.eventdata.queryName", "data.win.eventdata.destinationHostname", "dns.question.name", "url.domain"),
    }
    if entity_type == "hash":
        return {"bool": {"should": [
            {"wildcard": {"data.win.eventdata.hashes": f"*{value.upper()}*"}},
            {"term": {"file.hash.sha256": value.lower()}},
            {"term": {"process.hash.sha256": value.lower()}},
        ], "minimum_should_match": 1}}
    return {"bool": {"should": [{"term": {field: value}} for field in fields[entity_type]], "minimum_should_match": 1}}


TOOL_SCHEMAS = {
    "get_alerts": {"type": "object", "required": ["severity"], "properties": {"severity": {"type": "integer", "minimum": 0, "maximum": 16}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_alert_by_id": {"type": "object", "required": ["alert_id"], "properties": {"alert_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:@-]{1,256}$"}}},
    "search_logs": {"type": "object", "required": ["query"], "properties": {"query": {"type": "object"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_host_process_activity": {"type": "object", "required": ["host"], "properties": {"host": {"type": "string", "minLength": 1, "maxLength": 256}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_network_activity": {"type": "object", "required": ["host"], "properties": {"host": {"type": "string", "minLength": 1, "maxLength": 256}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_dns_activity": {"type": "object", "required": ["host"], "properties": {"host": {"type": "string", "minLength": 1, "maxLength": 256}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_host_file_activity": {"type": "object", "required": ["host"], "properties": {"host": {"type": "string", "minLength": 1, "maxLength": 256}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_process_by_guid": {"type": "object", "required": ["process_guid"], "properties": {"process_guid": {"type": "string", "minLength": 1, "maxLength": 256}, "hours": {"type": "integer", "minimum": 1, "maximum": 168}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_entity_activity": {"type": "object", "required": ["entity_type", "value", "start_time", "end_time"], "properties": {"entity_type": {"type": "string", "enum": ["process_guid", "parent_process_guid", "registry_key", "file_path", "hash", "ip", "domain"]}, "value": {"type": "string", "minLength": 1, "maxLength": 256}, "agent_id": {"type": "string", "minLength": 1, "maxLength": 256}, "host": {"type": "string", "minLength": 1, "maxLength": 256}, "start_time": {"type": "string"}, "end_time": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_process_children": {"type": "object", "required": ["parent_process_guid"], "properties": {"parent_process_guid": {"type": "string", "minLength": 1, "maxLength": 256}, "hours": {"type": "integer", "minimum": 1, "maximum": 168}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_process_network_activity": {"type": "object", "required": ["process_guid"], "properties": {"process_guid": {"type": "string", "minLength": 1, "maxLength": 256}, "hours": {"type": "integer", "minimum": 1, "maximum": 168}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_sysmon_profile_events": {"type": "object", "required": ["process_guid", "agent_id", "start_time", "end_time", "event_ids", "relationship"], "properties": {"process_guid": {"type": "string", "minLength": 1, "maxLength": 256}, "agent_id": {"type": "string", "minLength": 1, "maxLength": 256}, "start_time": {"type": "string"}, "end_time": {"type": "string"}, "event_ids": {"type": "array", "items": {"type": "string"}}, "relationship": {"type": "string", "enum": ["actor", "child", "access"]}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_sysmon_profile_coverage": {"type": "object", "required": ["agent_id", "start_time", "end_time", "event_ids"], "properties": {"agent_id": {"type": "string", "minLength": 1, "maxLength": 256}, "start_time": {"type": "string"}, "end_time": {"type": "string"}, "event_ids": {"type": "array", "items": {"type": "string"}}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_sysmon_alert_coverage": {"type": "object", "required": ["agent_id", "start_time", "end_time", "event_ids"], "properties": {"agent_id": {"type": "string", "minLength": 1, "maxLength": 256}, "start_time": {"type": "string"}, "end_time": {"type": "string"}, "event_ids": {"type": "array", "items": {"type": "string"}}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_telemetry_status": {"type": "object", "required": [], "properties": {}},
    "get_sysmon_fixture_process": {"type": "object", "required": ["marker", "host", "process_id"], "properties": {"marker": {"type": "string", "minLength": 1, "maxLength": 256}, "host": {"type": "string", "minLength": 1, "maxLength": 256}, "process_id": {"type": "string", "pattern": "^[0-9]+$"}, "hours": {"type": "integer", "minimum": 1, "maximum": 24}}},
    "get_hash_activity": {"type": "object", "required": ["hash_value"], "properties": {"hash_value": {"type": "string", "minLength": 32, "maxLength": 128}, "hours": {"type": "integer", "minimum": 1, "maximum": 168}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_ip_activity": {"type": "object", "required": ["ip"], "properties": {"ip": {"type": "string", "minLength": 3, "maxLength": 45}, "hours": {"type": "integer", "minimum": 1, "maximum": 168}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_domain_activity": {"type": "object", "required": ["domain"], "properties": {"domain": {"type": "string", "minLength": 3, "maxLength": 253}, "hours": {"type": "integer", "minimum": 1, "maximum": 168}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
    "get_authentication_activity": {"type": "object", "required": [], "properties": {"user": {"type": "string", "minLength": 1, "maxLength": 256}, "source_ip": {"type": "string", "minLength": 1, "maxLength": 256}, "hours": {"type": "integer", "minimum": 1, "maximum": 168}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
}
