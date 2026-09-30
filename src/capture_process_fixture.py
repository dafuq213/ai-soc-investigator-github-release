"""Capture a live, marker-bound process scenario into a replayable evidence fixture.

The collector uses the same bounded Wazuh tool layer as the application. It
never labels a scenario benign or malicious; it records only observable facts
and coverage limitations for later analyst review.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

try:
    from .wazuh_tools import WazuhConfig, WazuhToolLayer
except ImportError:
    from wazuh_tools import WazuhConfig, WazuhToolLayer


def capture_fixture(tools: WazuhToolLayer, case_id: str, scenario: str, marker: str, host: str, timeout_seconds: int = 120, poll_seconds: int = 5) -> dict[str, Any]:
    """Wait for one Sysmon Event ID 1 whose command line contains *marker*."""
    if timeout_seconds < 1 or poll_seconds < 1:
        raise ValueError("timeout_seconds and poll_seconds must be positive")
    deadline = time.monotonic() + timeout_seconds
    marker_carrier: dict[str, Any] | None = None
    seed: dict[str, Any] | None = None
    last_result: dict[str, Any] | None = None
    while time.monotonic() <= deadline:
        last_result = tools.get_process_fixture_by_marker(marker, host, hours=1)
        marker_carrier = _find_seed(last_result, marker)
        if marker_carrier:
            seed = _select_seed(tools, scenario, marker_carrier)
        if seed:
            break
        time.sleep(poll_seconds)
    if not seed:
        detail = last_result.get("error") if isinstance(last_result, Mapping) else None
        raise RuntimeError(f"no Sysmon Event ID 1 containing marker {marker!r} was collected for host {host!r}; last tool error: {detail}")

    event_data = _eventdata(seed)
    agent_id = seed.get("agent_id")
    process_guid = event_data.get("processGuid")
    parent_guid = event_data.get("parentProcessGuid")
    if not agent_id or not process_guid:
        raise RuntimeError("captured seed lacks agent.id or processGuid")

    seed_result = _single_record_result(last_result or {}, seed)
    parent = tools.get_process_by_guid(parent_guid, agent_id=agent_id) if parent_guid else _not_collected("parent process GUID was absent from the seed")
    children = tools.get_process_children(process_guid, agent_id=agent_id)
    network = tools.get_process_network_activity(process_guid, agent_id=agent_id)
    return {
        "fixture_version": 1,
        "case_id": case_id,
        "scenario": scenario,
        "marker": marker,
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "expected_observables": {
            "seed_event_id": "1",
            "host": host,
            "agent_id": agent_id,
            "process_guid_present": True,
            "parent_process_guid_present": bool(parent_guid),
            "verdict": "not_prejudged",
        },
        "tool_results": {
            "seed": seed_result,
            "marker_carrier": _single_record_result(last_result or {}, marker_carrier) if marker_carrier and marker_carrier is not seed else None,
            "parent": parent,
            "children": children,
            "network": network,
        },
        "coverage": {
            "parent_process": _coverage(parent),
            "child_processes": _coverage(children),
            "process_network": _coverage(network),
        },
    }


def make_missing_parent_fixture(fixture: Mapping[str, Any], case_id: str) -> dict[str, Any]:
    """Create the deliberate broken-data case from a captured source fixture."""
    broken = copy.deepcopy(dict(fixture))
    broken["case_id"] = case_id
    broken["scenario"] = "missing_parent_guid"
    broken["expected_observables"] = dict(broken["expected_observables"])
    broken["expected_observables"]["parent_process_guid_present"] = False
    broken["expected_observables"]["required_limitation"] = "parent origin unknown because ParentProcessGuid is absent"
    seed_data = broken["tool_results"]["seed"]["data"][0]["event"]["data"]["win"]["eventdata"]
    for field in ("parentProcessGuid", "parentProcessId", "parentImage", "parentCommandLine", "parentUser"):
        seed_data.pop(field, None)
    broken["tool_results"]["parent"] = _not_collected("deliberately removed ParentProcessGuid for broken-data validation")
    broken["coverage"]["parent_process"] = "unavailable: deliberate missing ParentProcessGuid"
    return broken


def _find_seed(result: Mapping[str, Any], marker: str) -> dict[str, Any] | None:
    if not result.get("ok"):
        return None
    for record in result.get("data", []):
        fields = _eventdata(record)
        system = _system(record)
        if system.get("eventID") == "1" and marker in str(fields.get("commandLine", "")):
            return record
    return None


def _select_seed(tools: WazuhToolLayer, scenario: str, marker_carrier: Mapping[str, Any]) -> dict[str, Any] | None:
    """Use the marker carrier itself unless the test scenario has a target child."""
    if scenario not in {"encoded_loopback", "process_discovery"}:
        return dict(marker_carrier)
    event_data = _eventdata(marker_carrier)
    process_guid, agent_id = event_data.get("processGuid"), marker_carrier.get("agent_id")
    if not process_guid or not agent_id:
        return None
    children = tools.get_process_children(process_guid, agent_id=agent_id)
    for record in children.get("data", []):
        fields = _eventdata(record)
        command_line = str(fields.get("commandLine", "")).lower()
        image = str(fields.get("image", "")).lower()
        if scenario == "encoded_loopback" and ("-encodedcommand" in command_line or "-enc " in command_line):
            return record
        if scenario == "process_discovery" and image.endswith("\\cmd.exe") and "whoami" in command_line:
            return record
    return None


def _eventdata(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return record.get("event", {}).get("data", {}).get("win", {}).get("eventdata", {})


def _system(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return record.get("event", {}).get("data", {}).get("win", {}).get("system", {})


def _single_record_result(result: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    meta = dict(result.get("meta", {}))
    meta.update({"count": 1, "total": 1, "truncated": False})
    return {"ok": True, "tool": "fixture_seed_selection", "data": [dict(record)], "meta": meta, "error": None}


def _not_collected(reason: str) -> dict[str, Any]:
    return {"ok": False, "tool": "not_collected", "data": [], "meta": {"count": 0}, "error": {"code": "coverage_gap", "message": reason}}


def _coverage(result: Mapping[str, Any]) -> str:
    if not result.get("ok"):
        return f"unavailable: {result.get('error', {}).get('message', 'tool failure')}"
    count = result.get("meta", {}).get("count", 0)
    if count:
        return f"observed: {count} matching record(s)"
    return "queried: no matching records; telemetry coverage is not independently established"


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture a live, marker-bound Windows process fixture through Wazuh tools")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--scenario", required=True, choices=("benign_process", "encoded_loopback", "process_discovery"))
    marker_source = parser.add_mutually_exclusive_group(required=True)
    marker_source.add_argument("--marker", help="Unique marker (avoid this form during live Sysmon capture because it appears in the collector command line)")
    marker_source.add_argument("--marker-env", help="Environment variable containing the marker")
    marker_source.add_argument("--marker-file", help="JSON output from run_process_fixture.ps1; recommended for live capture because the marker stays out of collector command lines")
    parser.add_argument("--host", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--make-missing-parent", action="store_true")
    args = parser.parse_args()
    if args.marker_file:
        marker = json.loads(Path(args.marker_file).read_text(encoding="utf-8")).get("marker")
    else:
        marker = os.getenv(args.marker_env) if args.marker_env else args.marker
    if not marker:
        raise ValueError("marker environment variable is unset or empty")
    fixture = capture_fixture(WazuhToolLayer(WazuhConfig.from_env()), args.case_id, args.scenario, marker, args.host, args.timeout_seconds)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2), encoding="utf-8")
    if args.make_missing_parent:
        broken_path = output.with_name(output.stem + "-missing-parent.json")
        broken_path.write_text(json.dumps(make_missing_parent_fixture(fixture, args.case_id + "-MISSING-PARENT"), indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "output": str(output), "case_id": args.case_id}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
