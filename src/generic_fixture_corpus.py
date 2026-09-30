"""Convert controlled telemetry fixtures into generic evidence-only packets.

No model is called. The captured fixture remains the source of truth; this
adapter merely gives it the same normalized-alert and entity-collection shape
used by the live investigator.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from .evidence_packet import build_evidence_packet
    from .generic_reporting import write_generic_report
    from .normalized_alert import normalize_alert
except ImportError:
    from evidence_packet import build_evidence_packet
    from generic_reporting import write_generic_report
    from normalized_alert import normalize_alert


FIXTURE_RELATIONSHIPS = {
    "parent": ("parent_process_origin", {}),
    "children": ("process_lineage", {"entity_type": "parent_process_guid"}),
    "network": ("process_lineage", {"entity_type": "process_guid"}),
    "marker_carrier": ("process_lineage", {"entity_type": "process_guid"}),
}


def build_generic_fixture_artifact(fixture_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Create an evidence-only generic artifact from one captured lab fixture."""
    source_path = Path(fixture_path)
    fixture = json.loads(source_path.read_text(encoding="utf-8"))
    if not isinstance(fixture, Mapping) or not isinstance(fixture.get("case_id"), str):
        raise ValueError("fixture requires a case_id")
    results = fixture.get("tool_results")
    seed_result = results.get("seed") if isinstance(results, Mapping) else None
    seed_data = seed_result.get("data") if isinstance(seed_result, Mapping) else None
    if not isinstance(seed_data, list) or not seed_data or not isinstance(seed_data[0], Mapping):
        raise ValueError("fixture seed result has no source record")
    normalized = normalize_alert(seed_data[0])
    executed = []
    for name, (kind, arguments) in FIXTURE_RELATIONSHIPS.items():
        result = results.get(name) if isinstance(results, Mapping) else None
        if not isinstance(result, Mapping):
            continue
        executed.append({
            "action_id": f"fixture_{name}", "kind": kind, "reason": f"Captured fixture {name} evidence",
            "executions": [{"arguments": arguments, "result": result}],
        })
    packet = build_evidence_packet(normalized, {"executed_actions": executed, "limitations": ["Offline fixture replay; no new Wazuh query was made."], "related_record_cap": 12})
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    case_id = fixture["case_id"]
    artifact_path = output / f"{case_id}.json"
    report_path = write_generic_report(packet, None, {"provider": "not_invoked", "model": "not_invoked", "invoked": False}, output / f"{case_id}.md", "evidence-only fixture corpus")
    artifact = {
        "benchmark_fixture": {"path": str(source_path), "scenario": fixture.get("scenario"), "marker": fixture.get("marker"), "expected_observables": fixture.get("expected_observables", {})},
        "normalized_alert": normalized, "evidence_packet": packet,
        "assessment": None, "assessment_error": "evidence-only fixture corpus",
        "model_execution": {"provider": "not_invoked", "model": "not_invoked", "invoked": False}, "prompt_audit": None,
    }
    artifact_path.write_text(json.dumps(artifact, indent=2, default=str), encoding="utf-8")
    return {"case_id": case_id, "artifact": str(artifact_path), "report": str(report_path), "evidence_count": len(packet["evidence"])}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build generic evidence-only artifacts from controlled fixtures")
    parser.add_argument("--fixture", action="append", required=True)
    parser.add_argument("--output-dir", default="data/benchmark_corpus")
    args = parser.parse_args()
    results, failures = [], []
    for fixture in args.fixture:
        try:
            results.append(build_generic_fixture_artifact(fixture, args.output_dir))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failures.append({"fixture": fixture, "error": str(exc)})
    print(json.dumps({"results": results, "failures": failures}, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
