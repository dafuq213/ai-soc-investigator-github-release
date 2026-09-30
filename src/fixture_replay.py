"""Replay captured process fixtures through the deterministic investigation path.

This module intentionally makes no Wazuh or LLM calls. It verifies that saved
source evidence produces the same canonical case, transformations, correlation
output, and evidence-only analyst report every time.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from .assessment import AssessmentPipeline, VerifiedAssessment
    from .case_models import CaseBuilder, InvestigationCase
    from .correlation import attach_deterministic_correlations
    from .evidence_transforms import decode_powershell_commands
    from .verified_reporting import write_verified_report
except ImportError:
    from assessment import AssessmentPipeline, VerifiedAssessment
    from case_models import CaseBuilder, InvestigationCase
    from correlation import attach_deterministic_correlations
    from evidence_transforms import decode_powershell_commands
    from verified_reporting import write_verified_report


def replay_fixture(fixture: Mapping[str, Any]) -> tuple[InvestigationCase, VerifiedAssessment]:
    """Build a case only from saved, tool-shaped fixture results."""
    case_id = fixture.get("case_id")
    results = fixture.get("tool_results")
    if not isinstance(case_id, str) or not case_id or not isinstance(results, Mapping):
        raise ValueError("fixture requires case_id and tool_results")
    seed = results.get("seed")
    if not isinstance(seed, Mapping):
        raise ValueError("fixture requires a seed tool result")
    case = CaseBuilder.from_seed_result(case_id, seed)
    _add_result(case, "get_process_by_guid", results.get("parent"), {"relationship": "parent"})
    _add_result(case, "get_process_children", results.get("children"), {"relationship": "children"})
    _add_result(case, "get_process_network_activity", results.get("network"), {"relationship": "process_network"})
    case.correlations["fixture"] = {
        "scenario": fixture.get("scenario"),
        "marker": fixture.get("marker"),
        "expected_observables": fixture.get("expected_observables", {}),
        "coverage": fixture.get("coverage", {}),
    }
    decode_powershell_commands(case)
    attach_deterministic_correlations(case)
    case.correlations["fixture"] = {
        "scenario": fixture.get("scenario"),
        "marker": fixture.get("marker"),
        "expected_observables": fixture.get("expected_observables", {}),
        "coverage": fixture.get("coverage", {}),
    }
    return case, AssessmentPipeline.evidence_only()


def _add_result(case: InvestigationCase, tool: str, result: Any, arguments: Mapping[str, Any]) -> None:
    if not isinstance(result, Mapping):
        return
    case.add_tool_result(tool, arguments, result)


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay a captured process fixture without Wazuh or an LLM")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output-dir", default="data/cases")
    args = parser.parse_args()
    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    case, assessment = replay_fixture(fixture)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report = write_verified_report(case, assessment, output / f"{case.case_id}.md")
    (output / f"{case.case_id}.json").write_text(json.dumps({"case": case.to_dict(), "assessment": assessment.__dict__}, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"ok": True, "case_id": case.case_id, "report": str(report), "evidence_count": len(case.evidence)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
