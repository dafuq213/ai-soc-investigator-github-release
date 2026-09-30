"""Replay one real archive sample per Sysmon profile without an LLM.

Archive samples validate profile collection and normalized dossier generation.
They are intentionally labelled as telemetry replays, not Wazuh alert cases:
normal Sysmon events need not have triggered a detection rule.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

try:
    from .assessment_dossier import build_dossier
    from .case_models import CaseBuilder
    from .correlation import attach_deterministic_correlations
    from .sysmon_profile_contracts import PROFILE_BY_EVENT_ID
    from .telemetry_profiles import SysmonProfileCollector
    from .wazuh_tools import WazuhConfig, WazuhToolLayer
except ImportError:
    from assessment_dossier import build_dossier
    from case_models import CaseBuilder
    from correlation import attach_deterministic_correlations
    from sysmon_profile_contracts import PROFILE_BY_EVENT_ID
    from telemetry_profiles import SysmonProfileCollector
    from wazuh_tools import WazuhConfig, WazuhToolLayer


def replay_samples(tools: Any, agent_id: str, start_time: str, end_time: str, context_hours: int = 1, limit: int = 5) -> list[dict[str, Any]]:
    """Collect and normalize one archive seed for every supported Event ID."""
    results: list[dict[str, Any]] = []
    for event_id, profile_id in PROFILE_BY_EVENT_ID.items():
        seed_result = tools.get_sysmon_profile_coverage(agent_id, start_time, end_time, [event_id], limit=1)
        records = seed_result.get("data") if isinstance(seed_result.get("data"), list) else []
        if not seed_result.get("ok") or not records:
            results.append({"event_id": event_id, "profile_id": profile_id, "status": "not_replayed", "error": seed_result.get("error")})
            continue
        seed_envelope = dict(seed_result)
        seed_envelope["data"] = [records[0]]
        case = CaseBuilder.from_seed_result(f"PROFILE-REPLAY-SYSMON-{event_id}", seed_envelope)
        SysmonProfileCollector(tools).collect(case, hours=context_hours, limit=limit)
        attach_deterministic_correlations(case)
        dossier = build_dossier(case)
        observation = dossier.get("profile_observation")
        results.append({
            "event_id": event_id,
            "profile_id": profile_id,
            "status": "replayed",
            "source_kind": "wazuh_archive_sample_not_alert",
            "seed_archive_document_id": case.seed_alert_id,
            "evidence_count": len(case.evidence),
            "tool_history": list(case.tool_history),
            "profile_observation": observation,
            "dossier": dossier,
            "case": case.to_dict(),
        })
    return results


def write_replays(replays: list[Mapping[str, Any]], output_dir: str | Path) -> Path:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    path = target / "sysmon_profile_replays.json"
    path.write_text(json.dumps(replays, indent=2, default=str), encoding="utf-8")
    lines = ["# Sysmon profile archive replays", "", "These are real Wazuh archive samples replayed through the profile collector. They are **not** Wazuh alert investigations and no LLM was called.", "", "| Event ID | Profile | Evidence records | Selected dossier fields |", "|---:|---|---:|---|"]
    for item in replays:
        if item.get("status") != "replayed":
            lines.append(f"| {item.get('event_id')} | {item.get('profile_id')} | — | `{item.get('status')}` |")
            continue
        fields = item.get("profile_observation", {}).get("fields", {}) if isinstance(item.get("profile_observation"), Mapping) else {}
        values = "; ".join(f"{key}={str(value)[:100]}" for key, value in fields.items())
        lines.append(f"| {item['event_id']} | `{item['profile_id']}` | {item['evidence_count']} | {values} |")
    (target / "sysmon_profile_replays.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay real Wazuh archive samples through supported Sysmon profiles")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--start-time", required=True)
    parser.add_argument("--end-time", required=True)
    parser.add_argument("--context-hours", type=int, default=1, choices=range(1, 169))
    parser.add_argument("--limit", type=int, default=5, choices=range(1, 26))
    parser.add_argument("--output-dir", default="data/profile_replays")
    args = parser.parse_args()
    replays = replay_samples(WazuhToolLayer(WazuhConfig.from_env()), args.agent_id, args.start_time, args.end_time, args.context_hours, args.limit)
    path = write_replays(replays, args.output_dir)
    print(json.dumps({"ok": True, "output": str(path), "replayed": sum(item["status"] == "replayed" for item in replays), "total": len(replays)}, indent=2))


if __name__ == "__main__":
    main()
