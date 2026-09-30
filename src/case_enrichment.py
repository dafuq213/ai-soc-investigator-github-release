"""Bounded evidence enrichment for canonical investigation cases."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from .case_models import InvestigationCase
    from .wazuh_tools import WazuhToolLayer
    from .evidence_transforms import decode_powershell_commands
except ImportError:
    from case_models import InvestigationCase
    from wazuh_tools import WazuhToolLayer
    from evidence_transforms import decode_powershell_commands


class CaseEnricher:
    """Collects only entity-derived process context; no LLM is involved."""
    def __init__(self, tools: WazuhToolLayer):
        self.tools = tools

    def enrich_process_context(self, case: InvestigationCase, hours: int = 24, limit: int = 25) -> InvestigationCase:
        seed = case.evidence[0].record
        agent_id = seed.get("agent_id")
        parent_guids = sorted(case.entities["parent_process_guids"])
        process_guids = sorted(case.entities["process_guids"])
        for guid in parent_guids:
            self._add(case, "get_process_by_guid", {"process_guid": guid, "hours": hours, "limit": limit, "agent_id": agent_id})
        for guid in process_guids:
            self._add(case, "get_process_children", {"parent_process_guid": guid, "hours": hours, "limit": limit, "agent_id": agent_id})
            self._add(case, "get_process_network_activity", {"process_guid": guid, "hours": hours, "limit": limit, "agent_id": agent_id})
        if agent_id and parent_guids and seed.get("timestamp"):
            start, end = _window(seed["timestamp"], 2, 5)
            for guid in parent_guids:
                self._add(case, "get_process_siblings", {"parent_process_guid": guid, "agent_id": agent_id, "start_time": start, "end_time": end, "limit": limit}, contextual=True)
        decode_powershell_commands(case)
        return case

    def enrich_authentication_context(self, case: InvestigationCase, hours: int = 24, limit: int = 50) -> InvestigationCase:
        seed = case.evidence[0].record
        users = sorted(case.entities["users"])
        ips = sorted(case.entities["ips"])
        if users or ips:
            arguments: dict[str, Any] = {"hours": hours, "limit": limit, "agent_id": seed.get("agent_id")}
            if users:
                arguments["user"] = users[0]
            if ips:
                arguments["source_ip"] = ips[0]
            if seed.get("timestamp"):
                arguments["start_time"], arguments["end_time"] = _window(seed["timestamp"], 15, 15)
            self._add(case, "get_authentication_activity", arguments)
        return case

    def enrich_entity_context(self, case: InvestigationCase, hours: int = 24, limit: int = 25) -> InvestigationCase:
        """Collect a small, bounded set of context queries for any observed entities."""
        hosts = sorted(case.entities["hosts"])
        hashes = sorted(case.entities["hashes"])
        ips = sorted(case.entities["ips"])
        domains = sorted(case.entities["domains"])

        # A non-process seed may still benefit from host context. Process seeds already
        # collect exact GUID context, so avoid broad duplicate collection there.
        if hosts and not case.entities["process_guids"]:
            host = hosts[0]
            self._add(case, "get_host_process_activity", {"host": host, "limit": limit})
            self._add(case, "get_network_activity", {"host": host, "limit": limit})
            self._add(case, "get_dns_activity", {"host": host, "limit": limit})
            self._add(case, "get_host_file_activity", {"host": host, "limit": limit})
        if hashes:
            self._add(case, "get_hash_activity", {"hash_value": hashes[0], "hours": hours, "limit": limit})
        if ips:
            self._add(case, "get_ip_activity", {"ip": ips[0], "hours": hours, "limit": limit})
        if domains:
            self._add(case, "get_domain_activity", {"domain": domains[0], "hours": hours, "limit": limit})
        return case

    def _add(self, case: InvestigationCase, tool: str, arguments: dict[str, Any], contextual: bool = False) -> None:
        method = getattr(self.tools, tool, None)
        if not callable(method):
            result = {"ok": False, "data": [], "meta": {}, "error": {"code": "tool_unavailable", "message": f"{tool} is not available"}}
        else:
            result = method(**arguments)
        case.add_tool_result(tool, arguments, result, contextual=contextual)


def _window(value: str, before_minutes: int, after_minutes: int) -> tuple[str, str]:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ((timestamp - timedelta(minutes=before_minutes)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            (timestamp + timedelta(minutes=after_minutes)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"))
