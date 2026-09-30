"""Run one configured LLM against a frozen fixture and retain the full audit trail."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    from .assessment import VerifiedAssessment, evaluate_with_model
    from .fixture_prompt_audit import write_prompt_audit
    from .evidence_interpretation import EvidenceInterpretation, interpretation_prompt, verify_interpretation
    from .fixture_replay import replay_fixture
    from .llm_providers import provider_from_env
    from .verified_reporting import write_verified_report
except ImportError:
    from assessment import VerifiedAssessment, evaluate_with_model
    from fixture_prompt_audit import write_prompt_audit
    from evidence_interpretation import EvidenceInterpretation, interpretation_prompt, verify_interpretation
    from fixture_replay import replay_fixture
    from llm_providers import provider_from_env
    from verified_reporting import write_verified_report


def assess_fixture(fixture: Mapping[str, Any], output_dir: str | Path, produce: Callable[[Any], str], interpret: Callable[[Any], str] | None = None) -> tuple[VerifiedAssessment, dict[str, Any]]:
    """Audit the exact input, call one provider, verify, and render only verified output."""
    case, _ = replay_fixture(fixture)
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    audit = write_prompt_audit(dict(fixture), target)
    assessment = evaluate_with_model(case, produce)
    interpretation = EvidenceInterpretation(status="not_requested", items=[])
    interpretation_audit: dict[str, Any] | None = None
    if interpret:
        prompt = interpretation_prompt(case)
        prompt_path = target / f"{case.case_id}.interpretation-prompt.txt"
        prompt_path.write_text(prompt, encoding="utf-8")
        try:
            interpretation = verify_interpretation(case, interpret(case))
        except Exception as exc:
            interpretation = EvidenceInterpretation(status="rejected", items=[], error=f"model provider failed: {exc}")
        interpretation_audit = {"prompt": str(prompt_path), "prompt_sha256": __import__("hashlib").sha256(prompt.encode("utf-8")).hexdigest(), "status": interpretation.status, "error": interpretation.error}
    report = write_verified_report(case, assessment, target / f"{case.case_id}.llm-assessment.md", interpretation)
    result_path = target / f"{case.case_id}.llm-assessment.json"
    result_path.write_text(json.dumps({"case": case.to_dict(), "assessment": asdict(assessment), "interpretation": asdict(interpretation), "prompt_audit": audit, "interpretation_audit": interpretation_audit}, indent=2, default=str), encoding="utf-8")
    return assessment, {"case_id": case.case_id, "report": str(report), "result": str(result_path), **audit, "interpretation": interpretation_audit, "llm_called": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess a frozen fixture with the configured LLM provider and verifier")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output-dir", default="data/fixture_reports")
    args = parser.parse_args()
    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    provider = provider_from_env()
    # A fixture CLI run is one controlled assessment call, not an assessment
    # plus a second optional explanatory call.  This keeps it useful for local
    # regression work without accidentally doubling paid token usage.
    assessment, output = assess_fixture(fixture, args.output_dir, provider.assess)
    print(json.dumps({**output, "provider": type(provider).__name__, "model": getattr(provider, "model", None), "assessment_status": assessment.status, "verdict": assessment.verdict, "error": assessment.error}, indent=2))
    return 0 if assessment.status == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
