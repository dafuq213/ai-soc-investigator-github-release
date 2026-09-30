"""Reference-only LLM triage planner for any normalized Wazuh seed alert."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

try:
    from .case_models import InvestigationCase
    from .wazuh_tools import WazuhToolLayer
except ImportError:
    from case_models import InvestigationCase
    from wazuh_tools import WazuhToolLayer


REASON_CODES = {"establish_scope", "process_lineage", "process_network", "identity_sequence", "insufficient_data"}


@dataclass(frozen=True)
class TriageDecision:
    decision: str
    action_id: str | None
    reason_code: str

    @classmethod
    def from_json(cls, value: str | Mapping[str, Any], available: set[str]) -> "TriageDecision":
        raw = json.loads(value) if isinstance(value, str) else dict(value)
        if set(raw) != {"decision", "action_id", "reason_code"} or raw.get("decision") not in {"act", "stop"} or raw.get("reason_code") not in REASON_CODES:
            raise ValueError("triage decision has an invalid schema")
        action = raw.get("action_id")
        if raw["decision"] == "stop" and action is not None:
            raise ValueError("stop decision must not include an action")
        if raw["decision"] == "act" and (not isinstance(action, str) or action not in available):
            raise ValueError("triage action is not currently available")
        return cls(raw["decision"], action, raw["reason_code"])


class TriagePlanner:
    """Advertises fixed actions and resolves their arguments in code only."""
    def __init__(self, tools: WazuhToolLayer, hours: int = 24, limit: int = 25):
        self.tools, self.hours, self.limit = tools, hours, limit

    def seed_card(self, case: InvestigationCase, completed: set[str] | None = None) -> dict[str, Any]:
        seed = case.evidence[0].record
        event = _eventdata(seed)
        refs = {
            "seed.agent_id": seed.get("agent_id"), "seed.host": seed.get("host"), "seed.timestamp": seed.get("timestamp"),
            "seed.process_guid": event.get("processGuid"), "seed.parent_process_guid": event.get("parentProcessGuid"),
            "seed.user": event.get("user") or event.get("targetUserName"), "seed.source_ip": event.get("sourceIp") or event.get("ipAddress"),
        }
        actions = [item for item in self._actions(refs) if item["id"] not in (completed or set())]
        rule = seed.get("rule", {}) if isinstance(seed.get("rule"), Mapping) else {}
        return {"seed_id": "S1", "alert": {"rule_id": rule.get("id"), "level": rule.get("level"), "description": rule.get("description"), "timestamp": seed.get("timestamp")}, "available_refs": sorted(key for key, value in refs.items() if value), "available_actions": [{"id": item["id"], "purpose": item["purpose"]} for item in actions]}

    def run(self, case: InvestigationCase, produce: Callable[[dict[str, Any], dict[str, Any]], str], max_steps: int = 4) -> list[dict[str, Any]]:
        completed: set[str] = set()
        history: list[dict[str, Any]] = []
        for _ in range(max_steps):
            card = self.seed_card(case, completed)
            ledger = {"completed_action_ids": sorted(completed), "tool_results": [{"tool": item["tool"], "count": item.get("count", 0), "ok": item.get("ok", False)} for item in case.tool_history]}
            available = {item["id"] for item in card["available_actions"]}
            if not available:
                break
            try:
                decision = TriageDecision.from_json(produce(card, ledger), available)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                history.append({"status": "rejected", "error": str(exc)})
                break
            if decision.decision == "stop":
                history.append({"status": "stopped", "reason_code": decision.reason_code})
                break
            result = self._execute(case, decision.action_id or "")
            completed.add(decision.action_id or "")
            history.append({"status": "executed", "action_id": decision.action_id, "reason_code": decision.reason_code, "count": result.get("meta", {}).get("count", 0), "ok": result.get("ok", False)})
        case.correlations["triage_planner"] = history
        return history

    def _actions(self, refs: Mapping[str, Any]) -> list[dict[str, str]]:
        has = lambda *names: all(refs.get(name) for name in names)
        actions = []
        if has("seed.agent_id", "seed.parent_process_guid"):
            actions.append({"id": "ACT-PARENT", "purpose": "establish direct process lineage"})
        if has("seed.agent_id", "seed.process_guid"):
            actions.extend([{"id": "ACT-CHILDREN", "purpose": "collect direct child processes"}, {"id": "ACT-PROCESS-NET", "purpose": "collect process-linked network activity"}])
        if has("seed.agent_id", "seed.parent_process_guid", "seed.timestamp"):
            actions.append({"id": "ACT-SIBLINGS", "purpose": "collect bounded same-parent context"})
        if has("seed.agent_id", "seed.timestamp") and (refs.get("seed.user") or refs.get("seed.source_ip")):
            actions.append({"id": "ACT-AUTH", "purpose": "collect bounded authentication context"})
        return actions

    def _execute(self, case: InvestigationCase, action_id: str) -> dict[str, Any]:
        seed, event = case.evidence[0].record, _eventdata(case.evidence[0].record)
        agent_id = seed.get("agent_id")
        if action_id == "ACT-PARENT":
            args, tool, context = {"process_guid": event["parentProcessGuid"], "agent_id": agent_id, "hours": self.hours, "limit": self.limit}, "get_process_by_guid", False
        elif action_id == "ACT-CHILDREN":
            args, tool, context = {"parent_process_guid": event["processGuid"], "agent_id": agent_id, "hours": self.hours, "limit": self.limit}, "get_process_children", False
        elif action_id == "ACT-PROCESS-NET":
            args, tool, context = {"process_guid": event["processGuid"], "agent_id": agent_id, "hours": self.hours, "limit": self.limit}, "get_process_network_activity", False
        elif action_id == "ACT-SIBLINGS":
            start, end = _window(seed["timestamp"])
            args, tool, context = {"parent_process_guid": event["parentProcessGuid"], "agent_id": agent_id, "start_time": start, "end_time": end, "limit": self.limit}, "get_process_siblings", True
        elif action_id == "ACT-AUTH":
            start, end = _auth_window(seed["timestamp"])
            args, tool, context = {"agent_id": agent_id, "user": event.get("user") or event.get("targetUserName"), "source_ip": event.get("sourceIp") or event.get("ipAddress"), "start_time": start, "end_time": end, "limit": 50}, "get_authentication_activity", False
            args = {key: value for key, value in args.items() if value is not None}
        else:
            raise ValueError("unknown triage action")
        result = getattr(self.tools, tool)(**args)
        case.add_tool_result(tool, args, result, contextual=context)
        return result


def triage_prompt(seed_card: dict[str, Any], ledger: dict[str, Any]) -> str:
    return f"""You are the triage planner for a Wazuh investigation. Choose exactly one available action ID or stop.
Do not infer or provide a query, argument value, user, host, IP, GUID, or time range. The application resolves arguments.
Return exactly {{"decision":"act|stop","action_id":"ACT-...|null","reason_code":"establish_scope|process_lineage|process_network|identity_sequence|insufficient_data"}}.
SEED CARD: {json.dumps(seed_card, separators=(',', ':'))}
COLLECTION LEDGER: {json.dumps(ledger, separators=(',', ':'))}"""


def _eventdata(record: Mapping[str, Any]) -> Mapping[str, Any]:
    event = record.get("event", {}) if isinstance(record.get("event"), Mapping) else {}
    data = event.get("data", {}) if isinstance(event.get("data"), Mapping) else {}
    win = data.get("win", {}) if isinstance(data.get("win"), Mapping) else {}
    return win.get("eventdata", {}) if isinstance(win.get("eventdata"), Mapping) else {}


def _window(value: str) -> tuple[str, str]:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ((timestamp - timedelta(minutes=2)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), (timestamp + timedelta(minutes=5)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"))


def _auth_window(value: str) -> tuple[str, str]:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ((timestamp - timedelta(minutes=15)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), (timestamp + timedelta(minutes=15)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"))
