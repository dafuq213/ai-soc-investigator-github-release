"""Generate a field inventory from real, Sysmon-only Wazuh archive samples.

This is an operator/developer diagnostic, not an LLM tool.  It documents the
actual Wazuh field paths before a profile decides which small subset belongs in
an investigation dossier.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

try:
    from .sysmon_profile_contracts import PROFILE_BY_EVENT_ID, contract_for_event_id
    from .wazuh_tools import WazuhConfig, WazuhToolLayer
except ImportError:
    from sysmon_profile_contracts import PROFILE_BY_EVENT_ID, contract_for_event_id
    from wazuh_tools import WazuhConfig, WazuhToolLayer


# These classifications are deliberately small.  Every observed field is
# catalogued; only named candidates may later enter a profile-specific dossier.
def build_catalog(tools: Any, agent_id: str, start_time: str, end_time: str, sample_limit: int = 25) -> dict[str, Any]:
    """Return an inventory based only on real Sysmon records returned by tools."""
    profiles: list[dict[str, Any]] = []
    for event_id, profile_id in PROFILE_BY_EVENT_ID.items():
        result = tools.get_sysmon_profile_coverage(agent_id, start_time, end_time, [event_id], limit=sample_limit)
        if not result.get("ok"):
            profiles.append({"event_id": event_id, "profile_id": profile_id, "status": "query_failed", "error": result.get("error")})
            continue
        records = result.get("data") if isinstance(result.get("data"), list) else []
        profiles.append({
            "event_id": event_id,
            "profile_id": profile_id,
            "status": "observed" if records else "not_observed",
            "sample_count": len(records),
            "fields": _catalog_fields(event_id, records),
        })
    return {
        "catalog_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {"backend": "wazuh-archives", "agent_id": agent_id, "start_time": start_time, "end_time": end_time, "sample_limit": sample_limit},
        "profiles": profiles,
    }


def _catalog_fields(event_id: str, records: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    observed: dict[str, list[Any]] = defaultdict(list)
    for record in records:
        fields = _eventdata(record)
        for key, value in fields.items():
            observed[str(key)].append(value)
    return [
        {
            "field": f"data.win.eventdata.{key}",
            "observed_type": _type_name(values),
            "present_in_samples": len(values),
            "role": _field_role(event_id, key),
        }
        for key, values in sorted(observed.items())
    ]


def _eventdata(record: Mapping[str, Any]) -> Mapping[str, Any]:
    event = record.get("event")
    if not isinstance(event, Mapping):
        return {}
    data = event.get("data")
    win = data.get("win") if isinstance(data, Mapping) else None
    fields = win.get("eventdata") if isinstance(win, Mapping) else None
    return fields if isinstance(fields, Mapping) else {}


def _type_name(values: list[Any]) -> str:
    names = sorted({type(value).__name__ for value in values})
    return "|".join(names) if names else "unknown"


def _field_role(event_id: str, field: str) -> str:
    contract = contract_for_event_id(event_id)
    correlation_keys = {alias for _, aliases in contract.required_keys for alias in aliases} if contract else set()
    dossier_candidates = {alias for _, aliases in contract.dossier_fields for alias in aliases} if contract else set()
    if field in correlation_keys:
        return "correlation_key"
    if field in dossier_candidates:
        return "dossier_candidate"
    if field in {"utcTime", "processId", "parentProcessId", "sourceProcessId", "targetProcessId"}:
        return "supporting_context"
    return "raw_only"


def write_catalog(catalog: Mapping[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    """Write machine-readable and operator-readable forms of one catalog."""
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / "sysmon_field_catalog.json"
    markdown_path = target / "sysmon_field_catalog.md"
    json_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    lines = ["# Sysmon field catalog", "", "Generated from Wazuh archive samples. `raw_only` means collected in the archive but not proposed for the dossier.", ""]
    source = catalog["source"]
    lines.extend([f"- Agent: `{source['agent_id']}`", f"- Window: `{source['start_time']}` to `{source['end_time']}`", f"- Samples per Event ID: up to `{source['sample_limit']}`", ""])
    for profile in catalog["profiles"]:
        lines.extend([f"## Sysmon Event ID {profile['event_id']} — {profile['profile_id']}", ""])
        if profile["status"] != "observed":
            lines.extend([f"Status: `{profile['status']}`", ""])
            continue
        lines.extend([f"Samples observed: `{profile['sample_count']}`", "", "| Field | Type | Present | Role |", "|---|---|---:|---|"])
        for field in profile["fields"]:
            lines.append(f"| `{field['field']}` | `{field['observed_type']}` | {field['present_in_samples']} | `{field['role']}` |")
        lines.append("")
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, markdown_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a real Wazuh Sysmon field catalog")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--start-time", required=True, help="ISO UTC; maximum 24-hour window")
    parser.add_argument("--end-time", required=True, help="ISO UTC; maximum 24-hour window")
    parser.add_argument("--sample-limit", type=int, default=25)
    parser.add_argument("--output-dir", default="docs/generated")
    args = parser.parse_args()
    catalog = build_catalog(WazuhToolLayer(WazuhConfig.from_env()), args.agent_id, args.start_time, args.end_time, args.sample_limit)
    json_path, markdown_path = write_catalog(catalog, args.output_dir)
    print(json.dumps({"ok": True, "json": str(json_path), "markdown": str(markdown_path)}, indent=2))


if __name__ == "__main__":
    main()
