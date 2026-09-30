"""Re-render a generic investigation from an already audited model response.

This is a migration/quality-control tool, not a retry mechanism: it never
contacts an LLM.  It makes contract changes visible by applying the current
parser to the original audited response before writing an updated report.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

try:
    from .generic_assessment import parse_generic_assessment
    from .generic_reporting import write_generic_report
except ImportError:
    from generic_assessment import parse_generic_assessment
    from generic_reporting import write_generic_report


def replay_generic_artifact(path: str | Path, write: bool = False) -> dict[str, Any]:
    """Parse the saved response and optionally update its saved report/artifact."""
    artifact_path = Path(path)
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    if not isinstance(artifact, Mapping):
        raise ValueError("artifact must be a JSON object")
    saved_packet = artifact.get("evidence_packet")
    if not isinstance(saved_packet, Mapping):
        raise ValueError("artifact has no evidence packet")
    # Older generic artifacts predate preservation of Wazuh-provided MITRE
    # metadata in the evidence packet.  Replay may migrate only the exact
    # metadata already stored in the same artifact's normalized seed alert.
    packet = json.loads(json.dumps(saved_packet))
    normalized_source = artifact.get("normalized_alert", {}).get("source", {}) if isinstance(artifact.get("normalized_alert"), Mapping) else {}
    saved_mitre = normalized_source.get("mitre") if isinstance(normalized_source, Mapping) else None
    packet_source = packet.get("alert", {}).get("source") if isinstance(packet.get("alert"), Mapping) else None
    if isinstance(packet_source, dict) and isinstance(saved_mitre, Mapping) and not packet_source.get("mitre"):
        packet_source["mitre"] = dict(saved_mitre)
    audit = artifact.get("prompt_audit")
    response_path = audit.get("response_path") if isinstance(audit, Mapping) else None
    if not isinstance(response_path, str) or not response_path:
        raise ValueError("artifact has no saved model response audit")
    response_file = Path(response_path)
    if not response_file.is_absolute():
        response_file = artifact_path.parent / response_file
    response_audit = json.loads(response_file.read_text(encoding="utf-8"))
    response = response_audit.get("response") if isinstance(response_audit, Mapping) else None
    if not isinstance(response, str):
        raise ValueError("saved response audit has no response text")
    try:
        assessment = parse_generic_assessment(response, packet)
        validation_error = None
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        assessment = None
        validation_error = str(exc)
    result = {
        "case_id": artifact_path.stem,
        "written": write,
        "assessment_status": assessment["assessment_status"] if assessment else "rejected",
        "verdict": assessment["verdict"] if assessment else "not_assessed",
        "confidence": assessment["confidence"] if assessment else None,
        "quality_flags": [flag["code"] for flag in assessment["quality_flags"]] if assessment else [],
        "validation_error": validation_error,
    }
    if not write:
        return result
    rewritten = dict(artifact)
    rewritten["evidence_packet"] = packet
    prior = rewritten.get("assessment")
    rewritten["assessment"] = assessment
    rewritten["assessment_error"] = validation_error
    rewritten["assessment_replay"] = {
        "replayed_at_utc": f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}",
        "reason": "Offline replay of saved audited response against current generic assessment contract; no model request was made.",
        "previous_assessment_status": prior.get("assessment_status", "accepted") if isinstance(prior, Mapping) else None,
    }
    model = rewritten.get("model_execution") if isinstance(rewritten.get("model_execution"), Mapping) else {}
    write_generic_report(packet, assessment, model, artifact_path.with_suffix(".md"), validation_error)
    artifact_path.write_text(json.dumps(rewritten, indent=2, default=str), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay a saved generic assessment without calling an LLM")
    parser.add_argument("--case", action="append", required=True, help="Saved GENERIC-*.json artifact; repeat as needed")
    parser.add_argument("--write", action="store_true", help="Write the revalidated assessment and re-render its report")
    args = parser.parse_args()
    results = []
    failures = []
    for item in args.case:
        try:
            results.append(replay_generic_artifact(item, write=args.write))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failures.append({"case": item, "error": str(exc)})
    print(json.dumps({"written": args.write, "results": results, "failures": failures}, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
