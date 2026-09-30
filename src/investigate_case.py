"""V1 architecture entry point: Wazuh alert -> case -> enrichment -> verified report."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from .assessment import AssessmentPipeline, VerifiedAssessment, evaluate_with_model
    from .case_enrichment import CaseEnricher
    from .telemetry_profiles import SysmonProfileCollector
    from .case_models import CaseBuilder, InvestigationCase
    from .correlation import attach_deterministic_correlations
    from .verified_reporting import write_verified_report
    from .wazuh_tools import WazuhConfig, WazuhToolLayer
    from .qa_review import apply_quality_gate, review_with_model
    from .evidence_transforms import decode_powershell_commands
except ImportError:
    from assessment import AssessmentPipeline, VerifiedAssessment, evaluate_with_model
    from case_enrichment import CaseEnricher
    from telemetry_profiles import SysmonProfileCollector
    from case_models import CaseBuilder, InvestigationCase
    from correlation import attach_deterministic_correlations
    from verified_reporting import write_verified_report
    from wazuh_tools import WazuhConfig, WazuhToolLayer
    from qa_review import apply_quality_gate, review_with_model
    from evidence_transforms import decode_powershell_commands


def run_case_investigation(tools: WazuhToolLayer, alert_id: str, reasoning: dict[str, Any] | None, hours: int = 24, case_id: str | None = None, reasoning_producer: Callable[[InvestigationCase], str] | None = None, qa_output: dict[str, Any] | None = None, qa_producer: Callable[[InvestigationCase, VerifiedAssessment], str] | None = None) -> tuple[InvestigationCase, VerifiedAssessment]:
    seed = tools.get_alert_by_id(alert_id)
    if not seed.get("ok") or not seed.get("data"):
        raise ValueError("alert was not found")
    case = CaseBuilder.from_seed_result(case_id or f"CASE-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}", seed)
    # Profile selection and evidence collection are deterministic.  The live
    # model assesses the resulting dossier; it never controls collection.
    SysmonProfileCollector(tools).collect(case, hours=hours)
    if case.entities["process_guids"] and not case.correlations.get("telemetry_profiles"):
        # Legacy fallback for a non-Sysmon process source. It is intentionally
        # not used for a Sysmon seed because profiles own that collection.
        CaseEnricher(tools).enrich_process_context(case, hours=hours)
    if case.evidence[0].event_type == "authentication":
        CaseEnricher(tools).enrich_authentication_context(case, hours=hours)
    decode_powershell_commands(case)
    attach_deterministic_correlations(case)
    if reasoning_producer:
        assessment = evaluate_with_model(case, reasoning_producer)
    elif reasoning is not None:
        assessment = AssessmentPipeline().evaluate(case, reasoning)
    else:
        assessment = AssessmentPipeline.evidence_only()
    if qa_producer and assessment.status == "accepted":
        assessment = apply_quality_gate(assessment, review_with_model(case, assessment, qa_producer))
    elif qa_output is not None and assessment.status == "accepted":
        from .qa_review import QualityGate
        assessment = apply_quality_gate(assessment, QualityGate().review(case, assessment, qa_output))
    return case, assessment


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the verified V1 Wazuh investigation architecture")
    parser.add_argument("--alert-id", required=True)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--reasoning-file", help="Structured LLM JSON output to verify")
    qa_source = parser.add_mutually_exclusive_group()
    qa_source.add_argument("--qa-file", help="Structured QA critic JSON to apply after an accepted assessment")
    parser.add_argument("--hours", type=int, default=24, choices=range(1, 169))
    parser.add_argument("--case-id")
    args = parser.parse_args()
    reasoning = json.loads(Path(args.reasoning_file).read_text(encoding="utf-8")) if args.reasoning_file else None
    qa_output = json.loads(Path(args.qa_file).read_text(encoding="utf-8")) if args.qa_file else None
    tools = WazuhToolLayer(WazuhConfig.from_env())
    # This developer entry point only replays supplied JSON.  Live calls must
    # use investigate_wazuh, which records and caps paid-provider usage.
    producer = None
    qa_producer = None
    try:
        case, assessment = run_case_investigation(tools, args.alert_id, reasoning, args.hours, args.case_id, producer, qa_output, qa_producer)
    except ValueError as exc:
        print({"ok": False, "alert_id": args.alert_id, "message": str(exc)})
        return 2
    output_dir = Path(__file__).resolve().parent.parent / "data" / "cases"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{case.case_id}.json").write_text(json.dumps({"case": case.to_dict(), "assessment": asdict(assessment)}, indent=2, default=str), encoding="utf-8")
    report = write_verified_report(case, assessment, output_dir / f"{case.case_id}.md")
    print({"ok": True, "case_id": case.case_id, "assessment_status": assessment.status, "verdict": assessment.verdict, "evidence_count": len(case.evidence), "report": str(report)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
