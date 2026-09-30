"""Simulation-only containment proposals.

No function here contacts an endpoint, firewall, identity provider, or Wazuh
active-response service. These are deliberately auditable recommendations that
must be approved and implemented by a separate response integration.
"""
from __future__ import annotations

from typing import Any


RESPONSE_TOOL_SCHEMAS = {
    "isolate_host": {"type": "object", "required": ["host"], "properties": {"host": {"type": "string", "minLength": 1, "maxLength": 256}}},
    "block_ip": {"type": "object", "required": ["ip"], "properties": {"ip": {"type": "string", "minLength": 1, "maxLength": 45}}},
    "disable_user": {"type": "object", "required": ["username"], "properties": {"username": {"type": "string", "minLength": 1, "maxLength": 256}}},
}


class ResponseSimulator:
    def isolate_host(self, host: str) -> dict[str, Any]:
        return self._proposal("isolate_host", "host", host, "Network isolation would be sent to the endpoint-control system.")

    def block_ip(self, ip: str) -> dict[str, Any]:
        return self._proposal("block_ip", "ip", ip, "A block rule would be sent to the approved firewall or EDR integration.")

    def disable_user(self, username: str) -> dict[str, Any]:
        return self._proposal("disable_user", "username", username, "The identity-provider account would be disabled through an approved integration.")

    @staticmethod
    def _proposal(action: str, field: str, value: str, detail: str) -> dict[str, Any]:
        return {"ok": True, "tool": action, "data": [{"action": action, "target": {field: value}, "simulated": True, "requires_human_approval": True, "detail": detail}], "meta": {"count": 1, "simulation": True}, "error": None}
