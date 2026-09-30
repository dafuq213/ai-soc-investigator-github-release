"""Acceptance gate for the three captured process-modality proof cases.

This is deliberately not an LLM-quality benchmark. It proves the prerequisite:
the deterministic evidence path and analyst report do not overstate what the
captured telemetry can establish.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any, Mapping

try:
    from .fixture_replay import replay_fixture
    from .verified_reporting import write_verified_report
except ImportError:
    from fixture_replay import replay_fixture
    from verified_reporting import write_verified_report


CHECKS = {
    "parent_observed": "Parent process:",
    "parent_unknown": "The seed process has no ParentProcessGuid, so parent origin cannot be determined from this record.",
    "no_network_overclaim": "No process-linked network telemetry was returned; command text does not prove connection success.",
    "decoded_connection_attempt": "Test-NetConnection -ComputerName 127.0.0.1 -Port 65534",
}


def run_process_poc(manifest_path: str | Path) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if not isinstance(manifest, list) or len(manifest) != 3:
        raise ValueError("process POC manifest must contain exactly three cases")
    results = []
    for item in manifest:
        if not isinstance(item, Mapping) or not isinstance(item.get("fixture"), str) or not isinstance(item.get("checks"), list):
            raise ValueError("each manifest item requires fixture and checks")
        unsupported = set(item["checks"]) - (set(CHECKS) | {"evidence_only"})
        if unsupported:
            raise ValueError(f"unknown POC checks: {sorted(unsupported)}")
        fixture = json.loads((manifest_file.parent / item["fixture"]).read_text(encoding="utf-8"))
        case, assessment = replay_fixture(fixture)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        failures = []
        for check in item["checks"]:
            if check == "evidence_only":
                if assessment.status != "evidence_only" or assessment.verdict != "inconclusive" or assessment.accepted_claims or assessment.recommended_actions:
                    failures.append("evidence-only replay produced an assessment claim, action, or non-inconclusive verdict")
            elif CHECKS[check] not in report:
                failures.append(f"report did not satisfy {check}")
        results.append({"case_id": case.case_id, "passed": not failures, "failures": failures})
    passed = all(item["passed"] for item in results)
    return {"cases": len(results), "results": results, "poc_ready_for_llm_prompt_evaluation": passed}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic three-case process proof-of-concept gate")
    parser.add_argument("--manifest", default="benchmarks/process_poc_manifest.json")
    args = parser.parse_args()
    outcome = run_process_poc(args.manifest)
    print(json.dumps(outcome, indent=2))
    return 0 if outcome["poc_ready_for_llm_prompt_evaluation"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
